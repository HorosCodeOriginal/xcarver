/*
 * scanner.c — Moteur de scan haute performance v4
 *
 * Algorithme : Aho-Corasick multi-pattern multi-output
 *   - OChainNode + dict_suffix links (patterns multiples par état)
 *   - Overlap inter-thread MAX_PAT_LEN (patterns aux frontières)
 *   - Allocation heap des hits locaux (évite stack overflow pthread)
 *   - Guard uint64 underflow pour hstart = i+1-hlen
 *
 * API v4 — handle persistant (AC construit une seule fois) :
 *   xc_create()   build l'automate, retourne un handle opaque
 *   xc_scan()     scanne un buffer avec un handle existant (O(données), pas O(patterns))
 *   xc_free()     libère le handle
 *
 * API legacy (backward compat) :
 *   scan_buffer() construit + scanne + libère (coûteux si appelé par chunk)
 *
 * Compilation :
 *   Linux  : gcc -O3 -march=native -shared -fPIC -pthread -o scanner.so scanner.c
 *   macOS  : gcc -O3 -shared -fPIC -o scanner.dylib scanner.c
 *   Windows: gcc -O3 -shared -o scanner.dll scanner.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>

/* ── Limites ─────────────────────────────────────────────────────── */
#define MAX_PATTERNS    256          /* étendu de 128 → 256             */
#define MAX_PAT_LEN     32
#define ALPHA           256
#define AC_MAX_STATES   (MAX_PATTERNS * MAX_PAT_LEN + 1)
#define MAX_HITS_LOCAL  500000

/* ── Hit ─────────────────────────────────────────────────────────── */
typedef struct {
    uint64_t offset;
    uint64_t size;
    uint16_t pat_index;
    uint8_t  _pad[6];
} Hit;

/* ── Chaîne de sortie Aho-Corasick ──────────────────────────────── */
typedef struct {
    int16_t pat;    /* index du pattern */
    int16_t next;   /* prochain nœud, ou -1 */
} OChainNode;

/* ── État de l'automate ──────────────────────────────────────────── */
typedef struct {
    int32_t  go[ALPHA];
    int32_t  fail;
    int32_t  dict_suffix;
    int16_t  output_head;
    int16_t  _pad;
} ACState;

/* ── Automate complet ────────────────────────────────────────────── */
typedef struct {
    ACState    states[AC_MAX_STATES];
    OChainNode ochain[MAX_PATTERNS];
    int32_t    ochain_n;
    int32_t    size;
} AhoCorasick;

/* ═══════════════════════════════════════════════════════════════════
 * ScanHandle : patterns + automate pré-construit (immuable)
 * Construit une seule fois, réutilisé pour tous les chunks.
 * ═══════════════════════════════════════════════════════════════════ */
typedef struct {
    uint8_t      headers[MAX_PATTERNS][MAX_PAT_LEN];
    uint8_t      header_lens[MAX_PATTERNS];
    uint8_t      footers[MAX_PATTERNS][MAX_PAT_LEN];
    uint8_t      footer_lens[MAX_PATTERNS];
    uint64_t     max_sizes[MAX_PATTERNS];
    uint16_t     npats;
    AhoCorasick  ac;
} ScanHandle;

/* ── Contexte de scan (par appel à xc_scan) ──────────────────────── */
typedef struct {
    const ScanHandle *handle;
    const uint8_t    *data;
    uint64_t          data_len;
    uint64_t          base_offset;
    Hit              *hits;
    uint32_t          nhits;
    uint32_t          max_hits;
    pthread_mutex_t   mutex;
} ScanCtx;

typedef struct {
    ScanCtx  *ctx;
    uint64_t  start;
    uint64_t  end;
    uint64_t  report_end;
} WorkerArgs;

/* ── AC : init ───────────────────────────────────────────────────── */
static void ac_init(AhoCorasick *ac) {
    memset(&ac->states[0], 0xFF, sizeof(ACState));
    ac->states[0].fail        = 0;
    ac->states[0].dict_suffix = -1;
    ac->states[0].output_head = -1;
    ac->size     = 1;
    ac->ochain_n = 0;
}

/* ── AC : ajout pattern ──────────────────────────────────────────── */
static void ac_add_pattern(AhoCorasick *ac, const uint8_t *pat,
                            uint8_t plen, int16_t idx) {
    int32_t cur = 0;
    for (uint8_t i = 0; i < plen; i++) {
        uint8_t c = pat[i];
        if (ac->states[cur].go[c] == -1) {
            int32_t ns = ac->size++;
            memset(&ac->states[ns], 0xFF, sizeof(ACState));
            ac->states[ns].fail        = 0;
            ac->states[ns].dict_suffix = -1;
            ac->states[ns].output_head = -1;
            ac->states[cur].go[c]      = ns;
        }
        cur = ac->states[cur].go[c];
    }
    if (ac->ochain_n < MAX_PATTERNS) {
        int32_t node = ac->ochain_n++;
        ac->ochain[node].pat  = idx;
        ac->ochain[node].next = ac->states[cur].output_head;
        ac->states[cur].output_head = (int16_t)node;
    }
}

/* ── AC : construction des liens d'échec + dict_suffix ──────────── */
static void ac_build(AhoCorasick *ac) {
    int32_t queue[AC_MAX_STATES];
    int head = 0, tail = 0;

    for (int c = 0; c < ALPHA; c++) {
        if (ac->states[0].go[c] == -1) {
            ac->states[0].go[c] = 0;
        } else {
            int32_t s = ac->states[0].go[c];
            ac->states[s].fail        = 0;
            ac->states[s].dict_suffix = -1;
            queue[tail++] = s;
        }
    }

    while (head < tail) {
        int32_t r = queue[head++];
        for (int c = 0; c < ALPHA; c++) {
            int32_t s = ac->states[r].go[c];
            if (s == -1) {
                ac->states[r].go[c] = ac->states[ac->states[r].fail].go[c];
            } else {
                int32_t f = ac->states[r].fail;
                ac->states[s].fail = ac->states[f].go[c];

                int32_t fs = ac->states[s].fail;
                if (ac->states[fs].output_head != -1)
                    ac->states[s].dict_suffix = fs;
                else
                    ac->states[s].dict_suffix = ac->states[fs].dict_suffix;

                queue[tail++] = s;
            }
        }
    }
}

/* ── Worker thread ───────────────────────────────────────────────── */
static void *worker(void *arg) {
    WorkerArgs        *w    = (WorkerArgs *)arg;
    ScanCtx           *ctx  = w->ctx;
    const ScanHandle  *h    = ctx->handle;
    const uint8_t     *data = ctx->data;
    const AhoCorasick *ac   = &h->ac;

    Hit *local = (Hit *)malloc(MAX_HITS_LOCAL * sizeof(Hit));
    if (!local) return NULL;
    uint32_t nlocal = 0;

    int32_t state = 0;

    for (uint64_t i = w->start; i < w->end && nlocal < MAX_HITS_LOCAL; i++) {
        state = ac->states[state].go[data[i]];

        int32_t cur_state = state;
        while (cur_state != -1) {
            int16_t on = ac->states[cur_state].output_head;
            while (on != -1) {
                int16_t pi = ac->ochain[on].pat;
                on = ac->ochain[on].next;

                if (pi < 0 || pi >= (int16_t)h->npats) goto next_output;

                uint8_t  hlen   = h->header_lens[pi];
                if (i + 1 < (uint64_t)hlen) goto next_output;

                uint64_t hstart = i + 1 - hlen;
                if (hstart < w->start || hstart >= w->report_end) goto next_output;

                {
                    uint64_t abs_offset = ctx->base_offset + hstart;
                    uint64_t size       = 0;

                    if (h->footer_lens[pi] > 0) {
                        uint8_t  flen   = h->footer_lens[pi];
                        uint64_t flimit = (h->max_sizes[pi] > 0)
                            ? hstart + h->max_sizes[pi] : ctx->data_len;
                        if (flimit > ctx->data_len) flimit = ctx->data_len;

                        for (uint64_t j = i + 1; j + flen <= flimit; j++) {
                            if (memcmp(data + j, h->footers[pi], flen) == 0) {
                                size = j + flen - hstart;
                                break;
                            }
                        }
                        if (size == 0 && h->max_sizes[pi] > 0)
                            size = h->max_sizes[pi];
                    } else if (h->max_sizes[pi] > 0) {
                        size = h->max_sizes[pi];
                    }

                    local[nlocal++] = (Hit){
                        .offset    = abs_offset,
                        .size      = size,
                        .pat_index = (uint16_t)pi,
                    };
                    if (nlocal >= MAX_HITS_LOCAL) goto flush;
                }
                next_output:;
            }
            cur_state = ac->states[cur_state].dict_suffix;
        }
    }

flush:
    pthread_mutex_lock(&ctx->mutex);
    uint32_t avail = ctx->max_hits - ctx->nhits;
    uint32_t ncopy = nlocal < avail ? nlocal : avail;
    memcpy(ctx->hits + ctx->nhits, local, ncopy * sizeof(Hit));
    ctx->nhits += ncopy;
    pthread_mutex_unlock(&ctx->mutex);

    free(local);
    return NULL;
}

/* ── Lancement des threads ───────────────────────────────────────── */
static uint32_t _run_threads(ScanCtx *ctx, uint8_t nthreads) {
    pthread_t  *threads = (pthread_t  *)calloc(nthreads, sizeof(pthread_t));
    WorkerArgs *args    = (WorkerArgs *)calloc(nthreads, sizeof(WorkerArgs));
    if (!threads || !args) { free(threads); free(args); return 0; }

    uint64_t slice = ctx->data_len / nthreads;

    for (uint8_t t = 0; t < nthreads; t++) {
        uint64_t t_start      = (uint64_t)t * slice;
        uint64_t t_report_end = (t == nthreads - 1)
                                ? ctx->data_len : (uint64_t)(t + 1) * slice;
        uint64_t t_scan_end   = t_report_end + MAX_PAT_LEN;
        if (t_scan_end > ctx->data_len || t == nthreads - 1)
            t_scan_end = ctx->data_len;

        args[t] = (WorkerArgs){ ctx, t_start, t_scan_end, t_report_end };
        pthread_create(&threads[t], NULL, worker, &args[t]);
    }
    for (uint8_t t = 0; t < nthreads; t++)
        pthread_join(threads[t], NULL);

    free(threads);
    free(args);
    return ctx->nhits;
}

/* ═══════════════════════════════════════════════════════════════════
 * API publique v4 — Handle persistant
 * ═══════════════════════════════════════════════════════════════════ */

/* xc_create — construit l'automate une seule fois.
 * Retourne un handle opaque à passer à xc_scan().
 * Libérer avec xc_free() quand le carving est terminé.
 */
ScanHandle* xc_create(
    const uint8_t  *headers, const uint8_t  *hlens,
    const uint8_t  *footers, const uint8_t  *flens,
    const uint64_t *max_sizes, uint16_t npats
) {
    if (!headers || !hlens || npats == 0) return NULL;
    if (npats > MAX_PATTERNS) npats = MAX_PATTERNS;

    ScanHandle *h = (ScanHandle *)calloc(1, sizeof(ScanHandle));
    if (!h) return NULL;

    h->npats = npats;
    for (uint16_t i = 0; i < npats; i++) {
        uint8_t hl = hlens[i] < MAX_PAT_LEN ? hlens[i] : MAX_PAT_LEN;
        uint8_t fl = flens  && flens[i]  < MAX_PAT_LEN ? flens[i]  : 0;
        if (fl > MAX_PAT_LEN) fl = MAX_PAT_LEN;
        memcpy(h->headers[i], headers + (size_t)i * MAX_PAT_LEN, hl);
        h->header_lens[i] = hl;
        if (footers && fl > 0) {
            memcpy(h->footers[i], footers + (size_t)i * MAX_PAT_LEN, fl);
            h->footer_lens[i] = fl;
        }
        h->max_sizes[i] = max_sizes ? max_sizes[i] : 0;
    }

    ac_init(&h->ac);
    for (uint16_t i = 0; i < npats; i++)
        ac_add_pattern(&h->ac, h->headers[i], h->header_lens[i], (int16_t)i);
    ac_build(&h->ac);
    return h;
}

/* xc_scan — scanne un buffer avec un handle existant.
 * Peut être appelé des milliers de fois (un chunk = un appel) sans
 * reconstruire l'automate.
 */
uint32_t xc_scan(
    ScanHandle     *handle,
    const uint8_t  *data,    uint64_t data_len,  uint64_t base_offset,
    uint64_t       *out_hits, uint32_t max_hits,  uint8_t  nthreads
) {
    if (!handle || !data || data_len == 0 || nthreads == 0 || !out_hits) return 0;
    if (nthreads > 64) nthreads = 64;

    ScanCtx *ctx = (ScanCtx *)calloc(1, sizeof(ScanCtx));
    if (!ctx) return 0;
    ctx->hits = (Hit *)calloc(max_hits, sizeof(Hit));
    if (!ctx->hits) { free(ctx); return 0; }

    ctx->handle      = handle;
    ctx->data        = data;
    ctx->data_len    = data_len;
    ctx->base_offset = base_offset;
    ctx->max_hits    = max_hits;
    pthread_mutex_init(&ctx->mutex, NULL);

    _run_threads(ctx, nthreads);
    uint32_t n = ctx->nhits;

    for (uint32_t i = 0; i < n && i < max_hits; i++) {
        out_hits[i * 3 + 0] = ctx->hits[i].offset;
        out_hits[i * 3 + 1] = ctx->hits[i].size;
        out_hits[i * 3 + 2] = ctx->hits[i].pat_index;
    }

    pthread_mutex_destroy(&ctx->mutex);
    free(ctx->hits);
    free(ctx);
    return n;
}

/* xc_free — libère un handle créé par xc_create(). */
void xc_free(ScanHandle *handle) {
    free(handle);
}

/* xc_npats — nombre de patterns dans un handle (pour debug). */
uint16_t xc_npats(const ScanHandle *handle) {
    return handle ? handle->npats : 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * API legacy — scan_buffer (backward compat)
 * Construit + scanne + libère : O(AC build) par appel.
 * Préférer xc_create / xc_scan / xc_free pour de meilleures perfs.
 * ═══════════════════════════════════════════════════════════════════ */
uint32_t scan_buffer(
    const uint8_t  *data,
    uint64_t        data_len,
    uint64_t        base_offset,
    const uint8_t  *headers,
    const uint8_t  *hlens,
    const uint8_t  *footers,
    const uint8_t  *flens,
    const uint64_t *max_sizes,
    uint16_t        npats,
    uint64_t       *out_hits,
    uint32_t        max_hits,
    uint8_t         nthreads
) {
    ScanHandle *h = xc_create(headers, hlens, footers, flens, max_sizes, npats);
    if (!h) return 0;
    uint32_t n = xc_scan(h, data, data_len, base_offset, out_hits, max_hits, nthreads);
    xc_free(h);
    return n;
}
