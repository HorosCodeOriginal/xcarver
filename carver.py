#!/usr/bin/env python3
"""
carver.py — xCarver v4  File carver forensique haute performance.

Sources :
  Image raw (.dd/.img/.bin), device direct (/dev/sdb),
  E01/EnCase (pip install pyewf), RAM dump (.mem/.dmp/.vmem)

Moteurs :
  1. FS-aware  : FAT/NTFS/ext4/HFS+/APFS/… — noms + arborescence originaux
  2. Raw carver: Aho-Corasick C multithreadé, 110+ signatures, validators structurels

Nouvelles features v4 :
  - Handle persistant C (AC construit une seule fois, non par chunk)
  - Déduplication SHA256/64KB vraiment fonctionnelle FS↔Raw
  - Taille minimale par type (min_size dans SigDef)
  - Reprise de session (--resume)
  - Analyse entropique (--entropy-skip : skip zones chiffrées)
  - Mode CTF (--ctf : heatmap entropique HTML + détection overlays/polyglots)
  - Extraction récursive (--recursive)
  - Signatures externes JSON (--sig-dir)
  - Alignement secteur (--sector-align)
  - Max fichiers par type (--max-per-type)

Usage :
  python3 carver.py --list-devices
  python3 carver.py /dev/sda --output ./recovered/
  python3 carver.py image.dd --types jpeg,pdf,sqlite
  python3 carver.py image.dd --fs-only
  python3 carver.py image.dd --threads 8 --chunk-size 128
  python3 carver.py image.dd --ctf
  python3 carver.py image.dd --resume
  python3 carver.py image.dd --entropy-skip
"""

import sys, os, struct, ctypes, hashlib, json, math, datetime, argparse
import subprocess, platform, time, zipfile, gzip, bz2, shutil
from pathlib import Path
from collections import defaultdict

IS_WINDOWS = sys.platform == "win32"
IS_LINUX   = sys.platform.startswith("linux")
IS_MACOS   = sys.platform == "darwin"

_WIN_PTHREAD_DLL = "libwinpthread-1.dll"


def _configure_stdio():
    """UTF-8 console output (avoids cp1252 UnicodeEncodeError on Windows)."""
    if IS_WINDOWS:
        try:
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            ctypes.windll.kernel32.SetConsoleCP(65001)
        except Exception:
            pass
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


_configure_stdio()

# ── Couleurs ANSI ─────────────────────────────────────────────────
def _enable_ansi():
    if IS_WINDOWS:
        try:
            import ctypes as ct
            ct.windll.kernel32.SetConsoleMode(
                ct.windll.kernel32.GetStdHandle(-11), 7)
            return True
        except: return False
    return True

_C = _enable_ansi()
def _a(s): return s if _C else ""
R=_a("\033[0m"); B=_a("\033[1m"); DIM=_a("\033[2m")
GRN=_a("\033[32m"); YLW=_a("\033[33m"); RED=_a("\033[31m")
CYN=_a("\033[36m"); MAG=_a("\033[35m"); ORG=_a("\033[38;5;208m"); BLU=_a("\033[34m")

def fmt(b):
    if b == 0: return "0 o"
    for u, t in [("To", 2**40), ("Go", 2**30), ("Mo", 2**20), ("Ko", 2**10)]:
        if b >= t: return f"{b/t:.1f} {u}"
    return f"{b} o"

def _safe_name(s):
    return s.replace("/","_").replace("\\","_").replace(" ","_").lower()

# ── Imports locaux ────────────────────────────────────────────────
script_dir = Path(__file__).parent
sys.path.insert(0, str(script_dir))
from signatures import SIGNATURES, get_signatures, list_signatures, SigDef
from fs_parser  import parse_filesystem, reconstruct_file, FSType, DeletedEntry

MAX_PAT_LEN  = 32
CHUNK_SIZE   = 64 * 1024 * 1024     # 64 Mo
OVERLAP      = 8 * 1024             # Overlap entre chunks
MAX_HITS     = 200_000
ENTROPY_BLOCK = 512                 # bytes par bloc d'entropie
MAX_PER_DIR   = 2000                # max fichiers par sous-dossier
_MB = 1024 * 1024

# ════════════════════════════════════════════════════════════════════
# MOTEUR C — HANDLE PERSISTANT
# ════════════════════════════════════════════════════════════════════

_so: ctypes.CDLL | None = None
_use_persistent = False


def _find_mingw_bin() -> Path | None:
    gcc = shutil.which("gcc")
    if not gcc:
        return None
    for candidate in (Path(gcc).resolve().parent,
                      Path(gcc).resolve().parent.parent / "bin"):
        if (candidate / _WIN_PTHREAD_DLL).exists():
            return candidate
    return None


def _ensure_windows_scanner_deps() -> None:
    """Place MinGW pthread runtime beside scanner.dll for ctypes load."""
    if not IS_WINDOWS:
        return
    dest = script_dir / _WIN_PTHREAD_DLL
    if dest.exists():
        return
    mingw = _find_mingw_bin()
    if not mingw:
        return
    try:
        shutil.copy2(mingw / _WIN_PTHREAD_DLL, dest)
    except OSError:
        pass


def _load_scanner_lib(lib: Path) -> ctypes.CDLL:
    if IS_WINDOWS and hasattr(os, "add_dll_directory"):
        os.add_dll_directory(str(script_dir))
        mingw = _find_mingw_bin()
        if mingw:
            os.add_dll_directory(str(mingw))
    return ctypes.CDLL(str(lib))


def _compile_and_load():
    global _so, _use_persistent
    src = script_dir / "scanner.c"
    lib = script_dir / ("scanner.dll" if IS_WINDOWS else "scanner.so")

    if not src.exists():
        return None

    needs_compile = (not lib.exists() or
                     lib.stat().st_mtime < src.stat().st_mtime)

    if needs_compile:
        print(f"  {DIM}Compilation scanner C…{R}", end="", flush=True)
        cmd = ["gcc", "-O3", "-shared", "-pthread", f"-o{lib}", str(src)]
        if not IS_WINDOWS:
            cmd[3:3] = ["-fPIC", "-march=native"]
        r = subprocess.run(cmd, capture_output=True)
        if r.returncode != 0:
            print(f"\r  {YLW}Compilation échouée → mode Python pur{R}")
            if r.stderr:
                print(f"  {DIM}{r.stderr.decode(errors='replace')[:200]}{R}")
            return None
        print(f"\r  {GRN}Scanner C compilé (v4 — handle persistant){R}         ")
        if IS_WINDOWS:
            _ensure_windows_scanner_deps()

    try:
        _ensure_windows_scanner_deps()
        so = _load_scanner_lib(lib)

        # API v4 — handle persistant
        so.xc_create.restype  = ctypes.c_void_p
        so.xc_create.argtypes = [
            ctypes.c_char_p,                 # headers
            ctypes.c_char_p,                 # hlens
            ctypes.c_char_p,                 # footers
            ctypes.c_char_p,                 # flens
            ctypes.POINTER(ctypes.c_uint64), # max_sizes
            ctypes.c_uint16,                 # npats
        ]
        so.xc_scan.restype  = ctypes.c_uint32
        so.xc_scan.argtypes = [
            ctypes.c_void_p,                 # handle
            ctypes.c_char_p,                 # data
            ctypes.c_uint64,                 # data_len
            ctypes.c_uint64,                 # base_offset
            ctypes.POINTER(ctypes.c_uint64), # out_hits
            ctypes.c_uint32,                 # max_hits
            ctypes.c_uint8,                  # nthreads
        ]
        so.xc_free.restype  = None
        so.xc_free.argtypes = [ctypes.c_void_p]

        # API legacy (backward compat)
        so.scan_buffer.restype  = ctypes.c_uint32
        so.scan_buffer.argtypes = [
            ctypes.c_char_p, ctypes.c_uint64, ctypes.c_uint64,
            ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_char_p, ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_uint64), ctypes.c_uint16,
            ctypes.POINTER(ctypes.c_uint64), ctypes.c_uint32,
            ctypes.c_uint8,
        ]

        _so = so
        # Détecter si la nouvelle API est disponible
        try:
            _ = so.xc_npats
            _use_persistent = True
        except AttributeError:
            _use_persistent = False

        return so
    except OSError as e:
        print(f"  {YLW}Chargement lib échoué: {e}{R}")
        return None


def _build_sig_arrays(sigs: list):
    """Construit les tableaux ctypes plats pour les signatures."""
    npats    = len(sigs)
    headers  = bytearray(npats * MAX_PAT_LEN)
    hlens    = bytearray(npats)
    footers  = bytearray(npats * MAX_PAT_LEN)
    flens    = bytearray(npats)
    max_sizes = (ctypes.c_uint64 * npats)()

    for i, sig in enumerate(sigs):
        hl = min(len(sig.header), MAX_PAT_LEN)
        headers[i*MAX_PAT_LEN : i*MAX_PAT_LEN+hl] = sig.header[:hl]
        hlens[i] = hl
        if sig.footer:
            fl = min(len(sig.footer), MAX_PAT_LEN)
            footers[i*MAX_PAT_LEN : i*MAX_PAT_LEN+fl] = sig.footer[:fl]
            flens[i] = fl
        max_sizes[i] = sig.max_size or 0

    return bytes(headers), bytes(hlens), bytes(footers), bytes(flens), max_sizes


class PersistentScanner:
    """Wrapper autour du handle C persistant xc_create/xc_scan/xc_free."""

    def __init__(self, so, sigs: list):
        self._so   = so
        self._sigs = sigs
        self._hdl  = None
        self._arrs = _build_sig_arrays(sigs)
        self._out  = (ctypes.c_uint64 * (MAX_HITS * 3))()
        self._built = False

        h, hl, f, fl, ms = self._arrs
        hdl = so.xc_create(h, hl, f, fl, ms, len(sigs))
        if hdl:
            self._hdl   = hdl
            self._built = True

    def scan(self, data: bytes, base_offset: int, nthreads: int) -> list:
        if not self._built or not self._hdl:
            return _scan_python(data, base_offset, self._sigs)
        n = self._so.xc_scan(
            self._hdl, data, len(data), base_offset,
            self._out, MAX_HITS, nthreads
        )
        return [(self._out[i*3], self._out[i*3+1], self._out[i*3+2])
                for i in range(min(n, MAX_HITS))]

    def close(self):
        if self._hdl and self._built:
            try:
                self._so.xc_free(self._hdl)
            except Exception:
                pass
            self._hdl = None


def _scan_python(data: bytes, base_offset: int, sigs: list) -> list:
    """Fallback Python pur (lent, pour débogage ou sans GCC)."""
    hits = []
    for si, sig in enumerate(sigs):
        pos = 0
        while pos < len(data):
            idx = data.find(sig.header, pos)
            if idx == -1: break
            size = 0
            if sig.footer:
                lim = idx + sig.max_size if sig.max_size else len(data)
                fi  = data.find(sig.footer, idx + len(sig.header),
                                min(lim, len(data)))
                size = fi + len(sig.footer) - idx if fi != -1 else (sig.max_size or 0)
            elif sig.max_size:
                size = sig.max_size
            hits.append((base_offset + idx, size, si))
            pos = idx + max(len(sig.header), 1)
    return hits


# ════════════════════════════════════════════════════════════════════
# SOURCE READER
# ════════════════════════════════════════════════════════════════════

class SourceReader:
    def __init__(self, path: str):
        self.path    = path
        self.size    = 0
        self._f      = None
        self._ewf    = None
        self._is_ewf = path.lower().endswith((".e01", ".ex01", ".ewf"))
        self._is_dev = (path.startswith("/dev/") or
                        (IS_WINDOWS and path.startswith("\\\\.\\")))

    def open(self):
        if self._is_ewf:
            try:
                import pyewf
                self._ewf  = pyewf.handle()
                self._ewf.open(pyewf.glob(self.path))
                self.size  = self._ewf.get_media_size()
                return
            except ImportError:
                print(f"{RED}[!] pyewf non installé : pip install pyewf{R}")
                sys.exit(1)
        flags = os.O_RDONLY | (os.O_BINARY if IS_WINDOWS else 0)
        try:
            self._f = os.fdopen(os.open(self.path, flags), "rb")
        except PermissionError:
            print(f"{RED}[!] Permission refusée — relancer en root/sudo{R}")
            sys.exit(1)
        except FileNotFoundError:
            print(f"{RED}[!] Source introuvable : {self.path}{R}")
            sys.exit(1)
        if self._is_dev:
            self.size = self._device_size()
        else:
            self._f.seek(0, 2); self.size = self._f.tell(); self._f.seek(0)

    def _device_size(self) -> int:
        if IS_LINUX:
            import fcntl
            buf = ctypes.create_string_buffer(8)
            try:
                fcntl.ioctl(self._f.fileno(), 0x80081272, buf)
                return struct.unpack("Q", buf.raw)[0]
            except Exception:
                pass
        try:
            self._f.seek(0, 2); return self._f.tell()
        except Exception:
            return 0

    def read_at(self, offset: int, length: int) -> bytes:
        if self._ewf:
            self._ewf.seek(offset); return self._ewf.read(length)
        self._f.seek(offset); return self._f.read(length)

    def close(self):
        for obj in (self._ewf, self._f):
            if obj:
                try: obj.close()
                except Exception: pass


# ════════════════════════════════════════════════════════════════════
# DÉTECTION DES DEVICES
# ════════════════════════════════════════════════════════════════════

class DevInfo:
    def __init__(self, path, name, size, removable, model, fstype=""):
        self.path=path; self.name=name; self.size=size
        self.removable=removable; self.model=model; self.fstype=fstype


def list_devices() -> list:
    devs = []
    if IS_LINUX:
        try:
            r = subprocess.run(
                ["lsblk", "-J", "-b", "-o",
                 "NAME,SIZE,RM,MODEL,FSTYPE,TYPE,PATH"],
                capture_output=True, text=True)
            if r.returncode == 0:
                for d in json.loads(r.stdout).get("blockdevices", []):
                    _parse_lsblk(d, devs)
        except Exception: pass
    elif IS_WINDOWS:
        try:
            # PowerShell (wmic déprécié sur Win11)
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-PhysicalDisk | Select-Object DeviceId,Size,FriendlyName "
                 "| ConvertTo-Json"],
                capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                disks = json.loads(r.stdout) if r.stdout.strip() else []
                if isinstance(disks, dict): disks = [disks]
                for d in disks:
                    devid = d.get("DeviceId", "0")
                    path  = f"\\\\.\\PhysicalDrive{devid}"
                    size  = int(d.get("Size", 0))
                    model = d.get("FriendlyName", "?")
                    devs.append(DevInfo(path, path, size, False, model))
        except Exception: pass
    elif IS_MACOS:
        try:
            import plistlib
            r = subprocess.run(["diskutil", "list", "-plist"],
                               capture_output=True)
            for disk in plistlib.loads(r.stdout).get(
                    "AllDisksAndPartitions", []):
                name = disk.get("DeviceIdentifier", "")
                devs.append(DevInfo(f"/dev/{name}", name,
                                    disk.get("Size", 0), False, "?"))
        except Exception: pass
    return devs


def _parse_lsblk(d, out, depth=0):
    if d.get("type", "") in ("disk", "part", "loop", "lvm"):
        path = d.get("path", "") or f"/dev/{d.get('name','')}"
        out.append(DevInfo(
            path, d.get("name", "?"),
            int(d.get("size") or 0),
            d.get("rm") in (True, "1", "true"),
            d.get("model", "") or "",
            d.get("fstype", "") or ""))
    for c in d.get("children", []):
        _parse_lsblk(c, out, depth + 1)


def print_devices(devs: list):
    print(f"\n  {B}Dispositifs détectés :{R}\n")
    print(f"  {'Path':<26} {'Taille':>10}  {'Amov':>5}  {'FS':>10}  Modèle")
    print(f"  {'─'*26} {'─'*10}  {'─'*5}  {'─'*10}  {'─'*28}")
    for d in devs:
        rm = f"{GRN}oui{R}" if d.removable else f"{DIM}non{R}"
        print(f"  {CYN}{d.path:<26}{R} {fmt(d.size):>10}  "
              f"{rm:>5}  {d.fstype or '—':>10}  {d.model[:28]}")
    print()


# ════════════════════════════════════════════════════════════════════
# ENTROPIE
# ════════════════════════════════════════════════════════════════════

def _entropy(data: bytes) -> float:
    if not data: return 0.0
    counts = [0] * 256
    for b in data: counts[b] += 1
    n = len(data)
    return -sum(c/n * math.log2(c/n) for c in counts if c)


def _entropy_blocks(data: bytes, block_size: int = ENTROPY_BLOCK) -> list:
    """Retourne la liste des entropies par bloc."""
    return [_entropy(data[i:i+block_size])
            for i in range(0, len(data), block_size)]


def _high_entropy_ranges(data: bytes, threshold: float = 7.2,
                          block_size: int = ENTROPY_BLOCK) -> list:
    """Retourne les ranges [start, end) à haute entropie."""
    ranges, in_range, start = [], False, 0
    for i, e in enumerate(_entropy_blocks(data, block_size)):
        off = i * block_size
        if e >= threshold:
            if not in_range: start = off; in_range = True
        else:
            if in_range:
                ranges.append((start, off)); in_range = False
    if in_range:
        ranges.append((start, len(data)))
    return ranges


def _gen_entropy_heatmap(source: 'SourceReader', output_dir: Path,
                          block_size: int = 4096):
    """Génère une heatmap entropique HTML interactive."""
    out_path = output_dir / "entropy_heatmap.html"
    print(f"\n  {B}Génération heatmap entropique…{R}")

    blocks = []
    pos    = 0
    total  = source.size
    while pos < total:
        data  = source.read_at(pos, min(block_size * 256, total - pos))
        if not data: break
        for i in range(0, len(data), block_size):
            blk = data[i:i+block_size]
            if blk:
                blocks.append((pos + i, _entropy(blk)))
        pos  += len(data)
        pct   = int(pos / total * 100)
        print(f"\r  Entropie: {pct}%  {len(blocks)} blocs", end="", flush=True)

    print(f"\r  {GRN}{len(blocks)} blocs calculés{R}                       ")

    # Couleur : bleu (0) → vert (4) → jaune (6) → rouge (7) → blanc (8)
    def _color(e: float) -> str:
        if   e < 1.0: return "#003366"
        elif e < 3.0: return "#0066cc"
        elif e < 5.0: return "#00cc66"
        elif e < 6.5: return "#ffcc00"
        elif e < 7.0: return "#ff6600"
        elif e < 7.5: return "#ff0000"
        else:         return "#ffffff"

    cells_per_row = 256
    cells = []
    for off, ent in blocks:
        col = _color(ent)
        tip = f"0x{off:08x} | E={ent:.2f}"
        cells.append(
            f'<td style="background:{col};width:4px;height:4px;" '
            f'title="{tip}"></td>')

    rows = []
    for i in range(0, len(cells), cells_per_row):
        row_off = blocks[i][0] if i < len(blocks) else 0
        rows.append(
            f'<tr><td style="font:10px monospace;color:#888;padding-right:4px">'
            f'0x{row_off:08x}</td>' + "".join(cells[i:i+cells_per_row]) + "</tr>")

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>xCarver — Entropy Heatmap — {Path(source.path).name}</title>
<style>
body{{background:#111;color:#eee;font-family:monospace;margin:16px}}
table{{border-collapse:collapse}}
.legend{{display:flex;gap:12px;margin:12px 0}}
.lbox{{width:20px;height:20px;display:inline-block;vertical-align:middle}}
h1{{font-size:1.2em}}
</style></head>
<body>
<h1>Entropy Heatmap — {Path(source.path).name} ({fmt(source.size)})</h1>
<div class="legend">
  <span><span class="lbox" style="background:#003366"></span> 0–1 (uniforme)</span>
  <span><span class="lbox" style="background:#0066cc"></span> 1–3 (texte)</span>
  <span><span class="lbox" style="background:#00cc66"></span> 3–5 (données structurées)</span>
  <span><span class="lbox" style="background:#ffcc00"></span> 5–6.5 (compressé)</span>
  <span><span class="lbox" style="background:#ff6600"></span> 6.5–7 (compressé+)</span>
  <span><span class="lbox" style="background:#ff0000"></span> 7–7.5 (quasi-chiffré)</span>
  <span><span class="lbox" style="background:#ffffff;color:#111"></span> 7.5–8 (chiffré/random)</span>
</div>
<p style="font-size:0.85em">Bloc = {fmt(block_size)} | Survol pour offset + entropie</p>
<table>{"".join(rows)}</table>
</body></html>"""

    out_path.write_text(html, encoding="utf-8")
    print(f"  Heatmap → {GRN}{out_path}{R}")
    return out_path


# ════════════════════════════════════════════════════════════════════
# ANALYSE CTF
# ════════════════════════════════════════════════════════════════════

def _ctf_analyze(source: 'SourceReader', output_dir: Path):
    """Mode CTF : détection d'overlays, polyglots, strings cachées."""
    print(f"\n  {B}[CTF] Analyse forensique avancée…{R}\n")
    results = []

    # Overlay detection : lire les 512 derniers bytes
    if source.size > 1024:
        tail = source.read_at(source.size - 512, 512)
        # Chercher des signatures connues dans le tail
        from signatures import SIGNATURES as _SIGS
        found_tail = []
        for sig in _SIGS:
            if sig.header in tail:
                found_tail.append(sig.name)
        if found_tail:
            msg = f"[CTF] Overlay détecté en fin de fichier : {', '.join(found_tail)}"
            print(f"  {YLW}{msg}{R}")
            results.append({"type": "overlay", "found": found_tail,
                             "offset": source.size - 512})

    # Strings suspectes : chercher des patterns CTF communs
    patterns_ctf = [b"flag{", b"FLAG{", b"CTF{", b"picoCTF{",
                     b"CHTB{", b"HTB{", b"THM{", b"corCTF{",
                     b"-----BEGIN", b"PK\x03\x04"]
    chunk_size = min(10 * _MB, source.size)
    data_start = source.read_at(0, chunk_size)
    ctf_hits = {}
    for pat in patterns_ctf:
        pos = 0
        offsets = []
        while True:
            idx = data_start.find(pat, pos)
            if idx == -1: break
            offsets.append(idx)
            pos = idx + 1
        if offsets:
            ctf_hits[pat.decode(errors="replace")] = offsets[:10]

    if ctf_hits:
        print(f"  {GRN}[CTF] Patterns intéressants trouvés :{R}")
        for pat, offs in ctf_hits.items():
            offs_str = ", ".join(f"0x{o:x}" for o in offs[:5])
            print(f"    {CYN}{repr(pat)}{R} → {offs_str}")
            results.append({"type": "ctf_pattern", "pattern": pat,
                             "offsets": offs})

    # Fichiers polyglots : header A + footer/magic de B à l'intérieur
    from signatures import SIGNATURES as _SIGS2
    if len(data_start) > 64:
        sig_a = None
        for sig in _SIGS2:
            if data_start[:len(sig.header)] == sig.header:
                sig_a = sig; break
        if sig_a:
            print(f"  Type primaire : {GRN}{sig_a.name}{R}")
            inner_hits = []
            for sig_b in _SIGS2:
                if sig_b.name == sig_a.name: continue
                idx = data_start.find(sig_b.header, len(sig_a.header))
                if idx != -1:
                    inner_hits.append((sig_b.name, idx))
            if inner_hits:
                print(f"  {YLW}[CTF] Polyglot détecté! Signatures internes:{R}")
                for name, off in inner_hits[:10]:
                    print(f"    {CYN}{name}{R} @ 0x{off:x}")
                    results.append({"type": "polyglot",
                                    "outer": sig_a.name, "inner": name,
                                    "inner_offset": off})

    # Sauvegarde rapport CTF
    ctf_report = output_dir / "ctf_report.json"
    ctf_report.write_text(
        json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n  Rapport CTF → {GRN}{ctf_report}{R}")
    return results


# ════════════════════════════════════════════════════════════════════
# EXTRACTION RÉCURSIVE
# ════════════════════════════════════════════════════════════════════

_RECURSIVE_TYPES = {"ZIP-Office", "GZIP", "BZIP2", "7Z"}


def _extract_recursive(file_path: Path, output_dir: Path, depth: int = 0):
    """Extraction récursive depuis les archives trouvées (max 3 niveaux)."""
    if depth >= 3: return
    suffix = file_path.suffix.lower()
    try:
        if suffix in (".zip", ".docx", ".xlsx", ".pptx", ".apk", ".jar",
                      ".odt", ".epub"):
            out_sub = output_dir / f"{file_path.stem}_extracted"
            out_sub.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(file_path, "r") as zf:
                for info in zf.infolist():
                    if ".." in info.filename: continue  # path traversal guard
                    try:
                        zf.extract(info, out_sub)
                    except Exception: pass
        elif suffix == ".gz":
            out_file = output_dir / file_path.stem
            with gzip.open(file_path, "rb") as gz:
                data = gz.read(100 * _MB)
            out_file.write_bytes(data)
        elif suffix == ".bz2":
            out_file = output_dir / file_path.stem
            with bz2.open(file_path, "rb") as bz:
                data = bz.read(100 * _MB)
            out_file.write_bytes(data)
    except Exception:
        pass


# ════════════════════════════════════════════════════════════════════
# SIGNATURES EXTERNES JSON
# ════════════════════════════════════════════════════════════════════

def _load_external_sigs(sig_dir: Path) -> list:
    """Charge des signatures depuis des fichiers JSON dans sig_dir."""
    sigs = []
    if not sig_dir.is_dir():
        return sigs
    _MB = 1024 * 1024
    for f in sorted(sig_dir.glob("*.json")):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
            hdr_hex = d.get("header_hex", "").replace(" ", "")
            ftr_hex = d.get("footer_hex", "").replace(" ", "")
            if not hdr_hex:
                continue
            hdr = bytes.fromhex(hdr_hex)
            ftr = bytes.fromhex(ftr_hex) if ftr_hex else None
            max_mb = d.get("max_size_mb", 0)
            sigs.append(SigDef(
                d.get("name", f.stem),
                d.get("ext", ""),
                hdr, ftr,
                max_size=max_mb * _MB,
                min_size=d.get("min_size", 0),
                category=d.get("category", "custom"),
                description=d.get("description", f"External sig: {f.name}")
            ))
            print(f"  {GRN}Sig externe chargée : {d.get('name', f.stem)}{R}")
        except Exception as e:
            print(f"  {YLW}[WARN] {f.name}: {e}{R}")
    return sigs


# ════════════════════════════════════════════════════════════════════
# SESSION (REPRISE)
# ════════════════════════════════════════════════════════════════════

class Session:
    """Gestion de la reprise de session."""

    def __init__(self, output_dir: Path, source_path: str, source_size: int):
        self._path       = output_dir / ".xcarver_session.json"
        self.source_path = source_path
        self.source_size = source_size
        self.resume_pos  = 0          # offset de reprise du raw carving
        self.counters    = defaultdict(int)

    def load(self) -> bool:
        """Charge la session existante. Retourne True si compatible."""
        if not self._path.exists(): return False
        try:
            d = json.loads(self._path.read_text(encoding="utf-8"))
            if (d.get("source") != self.source_path or
                    d.get("source_size") != self.source_size):
                print(f"  {YLW}Session incompatible (source différente) — ignorée{R}")
                return False
            self.resume_pos = d.get("resume_pos", 0)
            self.counters   = defaultdict(int, d.get("counters", {}))
            return True
        except Exception:
            return False

    def save(self, current_pos: int, counters: dict):
        """Sauvegarde la progression."""
        self.resume_pos = current_pos
        self.counters   = defaultdict(int, counters)
        d = {
            "source":      self.source_path,
            "source_size": self.source_size,
            "resume_pos":  current_pos,
            "counters":    dict(counters),
            "saved_at":    datetime.datetime.now().isoformat(),
        }
        try:
            self._path.write_text(
                json.dumps(d, indent=2), encoding="utf-8")
        except Exception:
            pass

    def clear(self):
        try: self._path.unlink()
        except Exception: pass


def _rebuild_seen_hashes(output_dir: Path) -> set:
    """Relit les fichiers existants pour reconstruire le set de dedup."""
    seen = set()
    print(f"  {DIM}Reconstruction hashes existants…{R}", end="", flush=True)
    n = 0
    for f in output_dir.rglob("*"):
        if f.is_file() and f.suffix != ".json" and f.name != ".xcarver_session.json":
            try:
                chunk = f.read_bytes()[:65536]
                seen.add(hashlib.sha256(chunk).hexdigest())
                n += 1
            except Exception:
                pass
    print(f"\r  {GRN}{n} fichiers existants indexés (dedup){R}                ")
    return seen


# ════════════════════════════════════════════════════════════════════
# OUTPUT DIRECTORY MANAGER
# ════════════════════════════════════════════════════════════════════

class TypeDir:
    """Gère la limite MAX_PER_DIR fichiers par sous-dossier."""

    def __init__(self, base: Path):
        self._base    = base
        self._current = base
        self._count   = 0
        self._subdir  = 0
        base.mkdir(parents=True, exist_ok=True)

    def next_path(self, filename: str) -> Path:
        if self._count >= MAX_PER_DIR:
            self._subdir += 1
            self._current = self._base / f"part{self._subdir:03d}"
            self._current.mkdir(parents=True, exist_ok=True)
            self._count = 0
        self._count += 1
        return self._current / filename


# ════════════════════════════════════════════════════════════════════
# MOTEUR RAW CARVING
# ════════════════════════════════════════════════════════════════════

def carve_raw(source: SourceReader, sigs: list,
              output_dir: Path, threads: int,
              seen_hashes: set,
              session: Session | None = None,
              entropy_skip: bool = False,
              sector_align: bool = False,
              sector_size: int = 512,
              max_per_type: int = 0,
              recursive: bool = False,
              recursive_dir: Path | None = None) -> dict:

    so      = _compile_and_load()
    scanner = PersistentScanner(so, sigs) if so else None
    mode    = "C+AC persistant" if (scanner and scanner._built) else "Python pur"

    # Dossiers de sortie avec TypeDir
    type_dirs: dict[str, TypeDir] = {}
    for sig in sigs:
        d = output_dir / "raw" / _safe_name(sig.name)
        type_dirs[sig.name] = TypeDir(d)

    counters  = defaultdict(int, session.counters if session else {})
    stats     = defaultdict(int)
    t0        = time.perf_counter()
    total     = source.size

    # Reprise de session
    resume_pos = session.resume_pos if session else 0
    if resume_pos > 0:
        print(f"  {GRN}Reprise depuis 0x{resume_pos:x} ({fmt(resume_pos)}){R}")

    pos       = resume_pos
    last_pct  = -1
    save_every = 512 * 1024 * 1024   # sauvegarde session toutes les 512 Mo

    print(f"\n  {B}[2/2] Raw carving…{R}  [{mode}]  threads={threads}\n")

    while pos < total:
        chunk_len = min(CHUNK_SIZE, total - pos)
        try:
            data = source.read_at(pos, chunk_len)
        except OSError:
            pos += 512; stats["bad_sectors"] += 1; continue
        if not data: break

        # ── Entropy skip : skip zones >7.5 bits (chiffrées) ───────
        if entropy_skip:
            high_e = _high_entropy_ranges(data, threshold=7.5)
            if len(high_e) * ENTROPY_BLOCK >= len(data) * 0.8:
                # >80% du chunk est à haute entropie → skip
                stats["entropy_skipped"] += len(data)
                pos += len(data)
                continue

        # ── Scan ───────────────────────────────────────────────────
        if scanner:
            hits = scanner.scan(data, pos, threads)
        else:
            hits = _scan_python(data, pos, sigs)

        stats["hits_raw"] += len(hits)

        # ── Extraction ────────────────────────────────────────────
        for (offset, size, si) in hits:
            if si >= len(sigs): continue
            sig = sigs[int(si)]

            # Alignement secteur (optionnel)
            if sector_align:
                aligned = (int(offset) // sector_size) * sector_size
                if aligned != int(offset):
                    offset = aligned

            est_size = int(size) if size else min(
                sig.max_size or CHUNK_SIZE, total - int(offset))
            if est_size == 0: continue

            # Taille minimale rapide (avant lecture)
            if sig.min_size and est_size < sig.min_size:
                stats["too_small"] += 1; continue

            # Limite par type
            if max_per_type and counters[sig.name] >= max_per_type:
                continue

            try:
                file_data = source.read_at(int(offset), est_size)
            except OSError:
                continue

            if len(file_data) < max(len(sig.header), sig.min_size or 0):
                stats["too_small"] += 1; continue

            # ── Validation structurelle ───────────────────────────
            if sig.validator:
                try:
                    if not sig.validator(file_data):
                        stats["invalid"] += 1; continue
                except Exception:
                    stats["invalid"] += 1; continue

            # ── Taille minimale post-lecture ──────────────────────
            if sig.min_size and len(file_data) < sig.min_size:
                stats["too_small"] += 1; continue

            # ── Déduplication SHA256/64KB ─────────────────────────
            dedup_data = file_data[:65536]
            digest     = hashlib.sha256(dedup_data).hexdigest()
            if digest in seen_hashes:
                stats["dedup"] += 1; continue
            seen_hashes.add(digest)

            # ── Sauvegarde ────────────────────────────────────────
            counters[sig.name] += 1
            fname = (f"{_safe_name(sig.name)}"
                     f"_{int(offset):016x}"
                     f"_{counters[sig.name]:05d}{sig.ext}")
            out_path = type_dirs[sig.name].next_path(fname)

            try:
                out_path.write_bytes(file_data)
                stats[sig.name] += 1
            except OSError:
                seen_hashes.discard(digest)
                continue

            # ── Extraction récursive ──────────────────────────────
            if recursive and sig.name in _RECURSIVE_TYPES:
                rec_dir = (recursive_dir or output_dir / "recursive")
                _extract_recursive(out_path, rec_dir / _safe_name(sig.name))

        # ── Sauvegarde session périodique ─────────────────────────
        if session and pos - resume_pos > save_every:
            session.save(pos, dict(counters))
            resume_pos = pos

        # ── Progression ───────────────────────────────────────────
        pct = int((pos + len(data)) / total * 100)
        if pct != last_pct:
            elapsed = time.perf_counter() - t0
            speed   = (pos - (session.resume_pos if session else 0) + len(data)) / max(elapsed, 0.1)
            eta_s   = (total - pos - len(data)) / max(speed, 1)
            total_c = sum(v for k, v in stats.items()
                          if k not in ("bad_sectors","hits_raw","invalid",
                                       "too_small","dedup","entropy_skipped"))
            bw      = int(stats["bad_sectors"])
            dedup_c = int(stats["dedup"])
            bar_f   = int(pct / 100 * 36)
            bar     = f"{GRN}{'█'*bar_f}{'░'*(36-bar_f)}{R}"
            eta     = (f"{int(eta_s//3600)}h{int((eta_s%3600)//60)}m"
                       if eta_s > 3600
                       else (f"{int(eta_s//60)}m{int(eta_s%60)}s"
                             if eta_s > 5 else "~0s"))
            dedup_s = f"  {DIM}{dedup_c}dup{R}" if dedup_c else ""
            bad_s   = f"  {RED}{bw}bad{R}" if bw else ""
            print(f"\r  {bar} {pct:3d}%  {fmt(int(speed))}/s  "
                  f"ETA:{eta}  {GRN}{total_c}✓{R}"
                  f"{dedup_s}{bad_s}    ",
                  end="", flush=True)
            last_pct = pct

        pos += len(data) - (OVERLAP if pos + len(data) < total else 0)

    print(f"\r  {'█'*36} 100%  Terminé!                                              \n")

    if scanner:
        scanner.close()
    if session:
        session.save(total, dict(counters))

    return dict(stats)


# ════════════════════════════════════════════════════════════════════
# MOTEUR FS-AWARE
# ════════════════════════════════════════════════════════════════════

def carve_fs(source: SourceReader, output_dir: Path,
             seen_hashes: set) -> dict:
    print(f"\n  {B}[1/2] Analyse du système de fichiers…{R}")

    fs_type, deleted = parse_filesystem(source)

    if fs_type == FSType.UNKNOWN:
        print(f"  {YLW}FS non reconnu — raw carving uniquement{R}")
        return {"fs_type": "unknown", "found": 0}

    print(f"  FS détecté : {GRN}{fs_type.value}{R}  —  "
          f"{YLW}{len(deleted)}{R} entrées supprimées\n")

    fs_out = output_dir / "fs_recovered"
    fs_out.mkdir(parents=True, exist_ok=True)

    recovered = 0
    failed    = 0

    for entry in deleted:
        if entry.is_dir:
            (fs_out / entry.path.lstrip("/")).mkdir(parents=True,
                                                     exist_ok=True)
            continue

        safe_path = Path(entry.path.lstrip("/").replace("\\", "/"))
        out_path  = fs_out / safe_path
        out_path.parent.mkdir(parents=True, exist_ok=True)

        if reconstruct_file(source, entry, out_path):
            recovered += 1
            try:
                data_r  = out_path.read_bytes()
                h       = hashlib.sha256(data_r[:65536]).hexdigest()
                seen_hashes.add(h)
                entry.sha256       = hashlib.sha256(data_r).hexdigest()
                entry.recovered_to = str(out_path)
            except Exception:
                pass
        else:
            failed += 1

        total = len(deleted)
        pct   = int((recovered + failed) / max(total, 1) * 100)
        print(f"\r  {GRN}{recovered}{R} récup  {RED}{failed}{R} échecs  "
              f"[{pct}%]  {entry.name[:40]}              ",
              end="", flush=True)

    print(f"\r  {GRN}{recovered}{R} fichiers récupérés avec noms originaux  "
          f"{RED}{failed} échecs{R}                              \n")

    # Index JSON
    index = [
        {"name": e.name, "path": e.path, "size": e.size,
         "mtime": str(e.mtime) if e.mtime else None,
         "ctime": str(e.ctime) if e.ctime else None,
         "sha256": e.sha256, "recovered_to": e.recovered_to}
        for e in deleted if not e.is_dir
    ]
    idx_path = fs_out / "index.json"
    idx_path.write_text(
        json.dumps(index, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"  Index FS → {idx_path}")

    return {"fs_type": fs_type.value,
            "found": len(deleted),
            "recovered": recovered,
            "failed": failed}


# ════════════════════════════════════════════════════════════════════
# RAPPORT
# ════════════════════════════════════════════════════════════════════

def render_report(fs_stats: dict, raw_stats: dict,
                  source: SourceReader, output_dir: Path, elapsed: float):
    sep2 = f"{B}{'═'*70}{R}"
    sep  = f"{DIM}{'─'*70}{R}"
    speed = source.size / max(elapsed, 1)

    raw_total = sum(v for k, v in raw_stats.items()
                    if k not in ("bad_sectors","hits_raw","invalid",
                                 "too_small","dedup","entropy_skipped"))

    print(f"\n{sep2}")
    print(f"  {B}RAPPORT — {Path(source.path).name}{R}")
    print(sep2)
    print(f"  Source      : {CYN}{source.path}{R}  ({fmt(source.size)})")
    print(f"  Durée       : {elapsed:.1f}s   Vitesse moy : {fmt(int(speed))}/s")
    print(f"  Bad sectors : {RED}{raw_stats.get('bad_sectors',0)}{R}  "
          f"Hits bruts : {raw_stats.get('hits_raw',0):,}  "
          f"Invalides : {YLW}{raw_stats.get('invalid',0)}{R}  "
          f"Trop petits : {YLW}{raw_stats.get('too_small',0)}{R}  "
          f"Dédupliqués : {DIM}{raw_stats.get('dedup',0)}{R}")
    if raw_stats.get("entropy_skipped", 0):
        print(f"  Entropy skip: {DIM}{fmt(raw_stats['entropy_skipped'])} ignorés "
              f"(zones chiffrées){R}")
    print()

    if fs_stats.get("fs_type", "unknown") != "unknown":
        print(f"  {B}FS-aware ({fs_stats['fs_type']}){R}")
        print(f"    Entrées supprimées : {YLW}{fs_stats.get('found',0)}{R}")
        print(f"    Récupérés          : {GRN}{fs_stats.get('recovered',0)}{R}")
        print(f"    Échecs             : {RED}{fs_stats.get('failed',0)}{R}")
        print()

    print(f"  {B}Raw carving{R}  ({GRN}{raw_total}{R} fichiers)\n")
    for name, cnt in sorted(raw_stats.items(), key=lambda x: x[1], reverse=True):
        if name in ("bad_sectors","hits_raw","invalid","too_small",
                    "dedup","entropy_skipped") or cnt == 0:
            continue
        ratio = cnt / max(raw_total, 1)
        bar_f = int(ratio * 24)
        bar   = f"{GRN}{'█'*bar_f}{'░'*(24-bar_f)}{R}"
        print(f"  {CYN}{name:<20}{R} {bar}  {GRN}{cnt:>5}{R}")

    print()
    print(f"  Sortie : {GRN}{output_dir.resolve()}{R}")
    print(sep2)
    print()

    report = {
        "source": source.path,
        "size":   source.size,
        "elapsed_s": round(elapsed, 2),
        "speed_bps": int(speed),
        "fs":     fs_stats,
        "raw":    dict(raw_stats),
    }
    rp = output_dir / "carving_report.json"
    rp.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"  {DIM}Rapport JSON → {rp}{R}\n")


# ════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="xCarver v4 — File carver forensique FS-aware + raw",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)

    parser.add_argument("source", nargs="?")
    parser.add_argument("--output",     "-o", default="./carved")
    parser.add_argument("--types",      "-t", default=None,
        help="Types/catégories : jpeg,pdf,image,document,all (défaut: all)")
    parser.add_argument("--list-devices","-l", action="store_true")
    parser.add_argument("--list-devices-json", action="store_true",
        help="Liste des devices en JSON (pour HorosCarver GUI)")
    parser.add_argument("--list-types",        action="store_true")
    parser.add_argument("--fs-only",           action="store_true",
        help="FS uniquement (pas de raw carving)")
    parser.add_argument("--raw-only",          action="store_true",
        help="Raw carving uniquement (pas de FS)")
    parser.add_argument("--threads",    type=int,
        default=min(6, os.cpu_count() or 1))
    parser.add_argument("--chunk-size", type=int, default=64,
        help="Taille chunk en Mo (défaut: 64)")

    # Nouvelles options v4
    parser.add_argument("--resume",     action="store_true",
        help="Reprendre une session précédente")
    parser.add_argument("--entropy-skip", action="store_true",
        help="Ignorer les zones à haute entropie (chiffrées)")
    parser.add_argument("--ctf",        action="store_true",
        help="Mode CTF : heatmap entropique + détection polyglots/overlays")
    parser.add_argument("--recursive",  action="store_true",
        help="Extraction récursive depuis les archives")
    parser.add_argument("--sector-align", action="store_true",
        help="Aligner les offsets sur les frontières de secteurs")
    parser.add_argument("--sector-size", type=int, default=512,
        help="Taille de secteur pour --sector-align (défaut: 512)")
    parser.add_argument("--max-per-type", type=int, default=0,
        help="Nombre maximum de fichiers par type (0=illimité)")
    parser.add_argument("--sig-dir",    default=None,
        help="Dossier de signatures JSON supplémentaires")
    parser.add_argument("--no-compile", action="store_true",
        help="Forcer le mode Python pur (pas de compilation C)")

    args = parser.parse_args()

    # ── Actions immédiates ────────────────────────────────────────
    if args.list_types:
        list_signatures(); return

    if args.list_devices_json:
        devs = list_devices()
        payload = [
            {"path": d.path, "name": d.name, "size": d.size,
             "removable": d.removable, "model": d.model, "fstype": d.fstype}
            for d in devs
        ]
        print(json.dumps(payload, ensure_ascii=False))
        return

    if args.list_devices:
        devs = list_devices()
        if devs: print_devices(devs)
        else:    print(f"\n  {YLW}Aucun device (root requis ?){R}\n")
        if not args.source: return

    if not args.source:
        parser.print_help(); sys.exit(1)

    global CHUNK_SIZE
    CHUNK_SIZE = args.chunk_size * 1024 * 1024

    # ── Chargement des signatures ─────────────────────────────────
    sigs = get_signatures(args.types)
    if args.sig_dir:
        ext_sigs = _load_external_sigs(Path(args.sig_dir))
        sigs     = sigs + ext_sigs

    # Désactiver la compilation si demandé
    if args.no_compile:
        global _so
        _so = None

    print(f"\n  {B}xCarver v4{R}")
    print(f"  Source   : {CYN}{args.source}{R}")
    print(f"  Sortie   : {args.output}")
    print(f"  Sigs     : {len(sigs)}  "
          f"Threads : {args.threads}  "
          f"Chunks : {args.chunk_size} Mo")

    if args.entropy_skip: print(f"  {YLW}Entropy-skip activé (zones chiffrées ignorées){R}")
    if args.ctf:          print(f"  {MAG}Mode CTF activé{R}")
    if args.recursive:    print(f"  {CYN}Extraction récursive activée{R}")
    if args.sector_align: print(f"  {DIM}Alignement secteur {args.sector_size}B{R}")

    source = SourceReader(args.source)
    source.open()
    if source.size == 0:
        print(f"{RED}[!] Taille source indéterminable{R}"); sys.exit(1)
    print(f"  Taille   : {fmt(source.size)}\n")

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Session ───────────────────────────────────────────────────
    session   = Session(output_dir, args.source, source.size)
    seen_hashes: set = set()

    if args.resume:
        loaded = session.load()
        if loaded:
            seen_hashes = _rebuild_seen_hashes(output_dir)
            print(f"  {GRN}Session chargée — reprise à "
                  f"0x{session.resume_pos:x}{R}")
        else:
            print(f"  {YLW}Pas de session à reprendre — démarrage normal{R}")

    # ── Heatmap entropique CTF ─────────────────────────────────────
    if args.ctf:
        _gen_entropy_heatmap(source, output_dir)
        _ctf_analyze(source, output_dir)

    t0        = time.perf_counter()
    fs_stats  = {}
    raw_stats = {}

    try:
        # Phase 1 : FS-aware
        if not args.raw_only:
            fs_stats = carve_fs(source, output_dir, seen_hashes)

        # Phase 2 : Raw carving
        if not args.fs_only:
            raw_stats = carve_raw(
                source, sigs, output_dir, args.threads,
                seen_hashes,
                session       = session if args.resume else None,
                entropy_skip  = args.entropy_skip,
                sector_align  = args.sector_align,
                sector_size   = args.sector_size,
                max_per_type  = args.max_per_type,
                recursive     = args.recursive,
                recursive_dir = output_dir / "recursive",
            )
    finally:
        source.close()
        if args.resume:
            session.clear()   # Nettoyer la session si terminé proprement

    elapsed = time.perf_counter() - t0
    render_report(fs_stats, raw_stats, source, output_dir, elapsed)


if __name__ == "__main__":
    main()
