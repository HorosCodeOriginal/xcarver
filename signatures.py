#!/usr/bin/env python3
"""
signatures.py — Base de signatures complète pour xCarver v4.
100+ types de fichiers, validators structurels stricts.
"""

import struct
import zlib

_KB = 1024
_MB = 1024 * 1024
_GB = 1024 * 1024 * 1024


class SigDef:
    def __init__(self, name, ext, header, footer=None, max_size=0,
                 min_size=0, validator=None, category="", description=""):
        self.name        = name
        self.ext         = ext
        self.header      = header
        self.footer      = footer
        self.max_size    = max_size
        self.min_size    = min_size      # taille minimale en bytes
        self.validator   = validator
        self.category    = category
        self.description = description


# ════════════════════════════════════════════════════════════════════
# VALIDATORS — définitions avant SIGNATURES
# Règle : retourner False si clairement invalide, True si probablement ok.
# Chaque validator reçoit les bytes extraits (peut être tronqué).
# ════════════════════════════════════════════════════════════════════

def _u8(d, o):   return d[o] if o < len(d) else 0
def _u16le(d,o): return struct.unpack_from("<H",d,o)[0] if o+2<=len(d) else 0
def _u16be(d,o): return struct.unpack_from(">H",d,o)[0] if o+2<=len(d) else 0
def _u32le(d,o): return struct.unpack_from("<I",d,o)[0] if o+4<=len(d) else 0
def _u32be(d,o): return struct.unpack_from(">I",d,o)[0] if o+4<=len(d) else 0


# ── Images ──────────────────────────────────────────────────────────

def _val_jpeg(d):
    if len(d) < 20 or d[:3] != b"\xFF\xD8\xFF": return False
    m = _u8(d, 3)
    # APP0-APPF, DQT, DHT, SOF0-SOF3, SOS, COM, DRI, DAC
    valid = set(range(0xE0, 0xF0)) | {0xDB, 0xC0, 0xC1, 0xC2, 0xC3,
                                       0xC4, 0xCC, 0xDA, 0xDD, 0xFE}
    if m not in valid: return False
    # Au moins 100 bytes (un JPEG vide a ~100 bytes)
    if len(d) < 100: return False
    # Essai de trouver un segment SOF ou SOS
    pos = 2
    limit = min(len(d), 65536)
    while pos < limit - 3:
        if d[pos] != 0xFF:
            break
        mk = d[pos + 1]
        if mk == 0xD9: return True   # EOI trouvé = complet
        if mk in (0x00, 0xFF):       # padding
            pos += 1; continue
        if mk in range(0xD0, 0xD8):  # RST markers
            pos += 2; continue
        if pos + 3 >= limit: break
        seg = _u16be(d, pos + 2)
        if seg < 2 or seg > 65535: break
        if mk in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7):  # SOF
            if seg >= 9:
                h_ = _u16be(d, pos + 5)
                w_ = _u16be(d, pos + 7)
                if h_ > 0 and w_ > 0 and h_ <= 65535 and w_ <= 65535:
                    return True
        pos += 2 + seg
    return True  # On a au moins le bon magic + marker valide


def _val_png(d):
    if len(d) < 33 or d[:8] != b"\x89PNG\r\n\x1a\n": return False
    # IHDR doit être le premier chunk (longueur=13 toujours)
    chunk_len = _u32be(d, 8)
    if chunk_len != 13: return False
    if d[12:16] != b"IHDR": return False
    w = _u32be(d, 16)
    h = _u32be(d, 20)
    if w == 0 or h == 0 or w > 65535 or h > 65535: return False
    ct = _u8(d, 25)
    if ct not in (0, 2, 3, 4, 6): return False
    cm = _u8(d, 26)
    if cm != 0: return False  # seule méthode valide = deflate
    # Vérifier le CRC de IHDR
    if len(d) >= 33:
        expected_crc = _u32be(d, 29)
        actual_crc   = zlib.crc32(d[12:29]) & 0xFFFFFFFF
        if expected_crc != actual_crc: return False
    return True


def _val_gif(d):
    if len(d) < 13: return False
    if d[:6] not in (b"GIF87a", b"GIF89a"): return False
    w = _u16le(d, 6)
    h = _u16le(d, 8)
    return w > 0 and h > 0 and w <= 65535 and h <= 65535


def _val_bmp(d):
    if len(d) < 26 or d[:2] != b"BM": return False
    file_size = _u32le(d, 2)
    if file_size < 26 or file_size > 500*_MB: return False
    reserved  = _u32le(d, 6)
    if reserved != 0: return False          # doit être 0
    px_offset = _u32le(d, 10)
    if px_offset < 14 or px_offset > file_size: return False
    dib = _u32le(d, 14)
    if dib not in (12, 40, 52, 56, 64, 108, 124): return False
    if dib >= 40 and len(d) >= 26:
        w = abs(struct.unpack_from("<i", d, 18)[0])
        h = abs(struct.unpack_from("<i", d, 22)[0])
        if w == 0 or w > 65535: return False
        if h == 0 or h > 65535: return False
        planes = _u16le(d, 26)
        if planes != 1: return False
    return True


def _val_tiff_le(d):
    if len(d) < 8 or d[:4] != b"II\x2A\x00": return False
    ifd0 = _u32le(d, 4)
    if ifd0 < 8 or ifd0 >= len(d) - 2: return False
    nentries = _u16le(d, ifd0) if ifd0 + 2 <= len(d) else 0
    return 1 <= nentries <= 4096


def _val_tiff_be(d):
    if len(d) < 8 or d[:4] != b"MM\x00\x2A": return False
    ifd0 = _u32be(d, 4)
    if ifd0 < 8 or ifd0 >= len(d) - 2: return False
    nentries = _u16be(d, ifd0) if ifd0 + 2 <= len(d) else 0
    return 1 <= nentries <= 4096


def _val_webp(d):
    if len(d) < 12: return False
    if d[:4] != b"RIFF": return False
    if d[8:12] != b"WEBP": return False
    riff_size = _u32le(d, 4)
    return riff_size >= 4


def _val_wav(d):
    if len(d) < 44: return False
    if d[:4] != b"RIFF": return False
    if d[8:12] != b"WAVE": return False
    if d[12:16] != b"fmt ": return False
    fmt_sz = _u32le(d, 16)
    if fmt_sz < 16: return False
    afmt = _u16le(d, 20)
    if afmt not in (1, 3, 6, 7, 17, 65534): return False  # PCM, float, alaw, ulaw, ADPCM, ext
    channels = _u16le(d, 22)
    if channels == 0 or channels > 64: return False
    sr = _u32le(d, 24)
    if sr < 1000 or sr > 384000: return False
    return True


def _val_avi(d):
    if len(d) < 12: return False
    if d[:4] != b"RIFF": return False
    if d[8:12] != b"AVI ": return False
    return True


def _val_aiff(d):
    if len(d) < 12: return False
    if d[:4] != b"FORM": return False
    return d[8:12] in (b"AIFF", b"AIFC")


def _val_psd(d):
    if len(d) < 26 or d[:4] != b"8BPS": return False
    version = _u16be(d, 4)
    if version not in (1, 2): return False      # PSB = version 2
    # Réservé : bytes 6-11 doivent être 0
    if any(d[6:12]): return False
    channels = _u16be(d, 12)
    if channels < 1 or channels > 56: return False
    h_ = _u32be(d, 14)
    w_ = _u32be(d, 18)
    return w_ > 0 and h_ > 0 and w_ <= 300000 and h_ <= 300000


def _val_ico(d):
    if len(d) < 22 or d[:4] != b"\x00\x00\x01\x00": return False
    count = _u16le(d, 4)
    if count == 0 or count > 20: return False
    if len(d) < 6 + count * 16: return False
    # Vérifier la première entrée du répertoire (16 bytes)
    # width(1) height(1) colors(1) reserved(1=0) planes(2) bpp(2) size(4) offset(4)
    width     = _u8(d, 6)   # 0 = 256px
    height    = _u8(d, 7)
    reserved  = _u8(d, 9)
    if reserved != 0: return False
    img_size  = _u32le(d, 14)
    img_offset= _u32le(d, 18)
    if img_size == 0 or img_offset < 6 + count * 16: return False
    return True


def _val_heic(d):
    if len(d) < 12: return False
    # Box: size(4) + "ftyp"(4) + brand(4)
    if d[4:8] != b"ftyp": return False
    brand = d[8:12]
    return brand in (b"heic", b"heis", b"hevc", b"mif1", b"msf1",
                     b"hevx", b"hevm", b"hevo")


def _val_avif(d):
    if len(d) < 12 or d[4:8] != b"ftyp": return False
    brand = d[8:12]
    return brand in (b"avif", b"avis")


def _val_cr2(d):
    if len(d) < 10: return False
    if d[:4] != b"II\x2A\x00": return False
    return d[8:10] == b"CR"


def _val_jxl(d):
    # Container uniquement (magic 12 bytes distinctif)
    return (len(d) >= 12 and
            d[:4] == b"\x00\x00\x00\x0C" and
            d[4:8] == b"JXL " and
            d[8:12] == b"\x0D\x0A\x87\x0A")


# ── Audio ────────────────────────────────────────────────────────────

def _val_mp3_id3(d):
    if len(d) < 10 or d[:3] != b"ID3": return False
    ver = _u8(d, 3)
    if ver not in (2, 3, 4): return False
    if _u8(d, 4) != 0: return False
    flags = _u8(d, 5)
    if flags & 0x0F: return False               # bits bas réservés
    sz = d[6:10]
    if any(b & 0x80 for b in sz): return False  # syncsafe: MSB=0
    total = ((sz[0]&0x7F)<<21)|((sz[1]&0x7F)<<14)|((sz[2]&0x7F)<<7)|(sz[3]&0x7F)
    return total < 500*_MB


def _val_mp3_sync(d):
    if len(d) < 4: return False
    b0, b1 = d[0], d[1]
    if b0 != 0xFF or (b1 & 0xE0) != 0xE0: return False
    version = (b1 >> 3) & 0x3
    if version == 1: return False
    layer   = (b1 >> 1) & 0x3
    if layer == 0: return False
    br_idx  = (d[2] >> 4) & 0xF
    sr_idx  = (d[2] >> 2) & 0x3
    if br_idx == 0xF or sr_idx == 0x3: return False
    if br_idx == 0: return False
    return True


def _val_ogg(d):
    if len(d) < 27 or d[:4] != b"OggS": return False
    version = _u8(d, 4)
    if version != 0: return False
    htype = _u8(d, 5)                # 0x02=first, 0x04=last, 0x00=cont
    if htype not in (0x00, 0x02, 0x04, 0x06): return False
    return True


def _val_flac(d):
    if len(d) < 42 or d[:4] != b"fLaC": return False
    # STREAMINFO block: type=0, length=34
    block_header = _u32be(d, 4)
    block_type   = (block_header >> 24) & 0x7F
    block_len    = block_header & 0xFFFFFF
    if block_type != 0 or block_len != 34: return False
    min_bs = _u16be(d, 8)
    max_bs = _u16be(d, 10)
    if min_bs < 16 or max_bs < min_bs: return False
    sr     = (_u8(d, 18) << 12) | (_u8(d, 19) << 4) | (_u8(d, 20) >> 4)
    return 1000 <= sr <= 655350


def _val_aac(d):
    if len(d) < 7: return False
    if d[0] != 0xFF or (d[1] & 0xF0) != 0xF0: return False
    if (d[1] & 0x06) != 0x00: return False      # layer doit être 00
    sf_idx = (d[2] >> 2) & 0xF
    if sf_idx > 12: return False
    chan = ((d[2] & 0x1) << 2) | (d[3] >> 6)
    if chan == 0 or chan > 7: return False
    return True


def _val_m4a(d):
    if len(d) < 12 or d[4:8] != b"ftyp": return False
    return d[8:12] in (b"M4A ", b"M4B ", b"M4P ", b"isom", b"mp42")


def _val_wma_wmv(d):
    return (len(d) >= 30 and
            d[:16] == b"\x30\x26\xB2\x75\x8E\x66\xCF\x11"
                       b"\xA6\xD9\x00\xAA\x00\x62\xCE\x6C")


# ── Vidéo ────────────────────────────────────────────────────────────

_FTYP_VIDEO_BRANDS = {
    b"isom", b"iso2", b"iso3", b"iso4", b"iso5", b"iso6",
    b"mp41", b"mp42", b"M4V ", b"M4VH", b"M4VP",
    b"avc1", b"f4v ", b"f4p ", b"MSNV",
    b"qt  ", b"3gp5", b"3gp6", b"3g2a", b"3g2b",
    b"hvc1", b"hevc", b"dash", b"cmfc",
}

def _val_mp4(d):
    if len(d) < 12: return False
    if d[4:8] != b"ftyp": return False
    brand = d[8:12]
    if brand in _FTYP_VIDEO_BRANDS: return True
    # Accepter aussi les marques inconnues si la box ftyp est cohérente
    box_size = _u32be(d, 0)
    return 8 <= box_size <= 512


def _val_mkv_webm(d):
    if len(d) < 31 or d[:4] != b"\x1A\x45\xDF\xA3": return False
    # Chercher DocType dans les 256 premiers bytes
    idx = d.find(b"webm", 0, 256)
    if idx != -1: return True
    idx = d.find(b"matroska", 0, 256)
    return idx != -1


def _val_flv(d):
    if len(d) < 9 or d[:3] != b"FLV": return False
    version = _u8(d, 3)
    if version not in (1, 2, 3, 4, 5): return False
    flags   = _u8(d, 4)
    if flags & 0xF8: return False        # bits 3-7 réservés
    offset  = _u32be(d, 5)
    return offset == 9


def _val_mpeg_ps(d):
    if len(d) < 8 or d[:4] != b"\x00\x00\x01\xBA": return False
    # MPEG-2: bits 6-7 de byte 4 = 01
    if (d[4] & 0xC0) == 0x40: return True   # MPEG-2 PS
    # MPEG-1: bits 6-7 = 00
    if (d[4] & 0xC0) == 0x00: return True   # MPEG-1 PS
    return False


def _val_mpeg_es(d):
    if len(d) < 8 or d[:4] != b"\x00\x00\x01\xB3": return False
    w = (d[4] << 4) | (d[5] >> 4)
    h = ((d[5] & 0xF) << 8) | d[6]
    return w > 0 and h > 0 and w <= 4096 and h <= 4096


def _val_ts(d):
    if len(d) < 4 or d[0] != 0x47: return False
    # Transport error indicator + payload unit start indicator + transport priority
    tei = (d[1] >> 7) & 1
    if tei: return False                    # paquet d'erreur
    pid = ((d[1] & 0x1F) << 8) | d[2]
    if pid > 0x1FFF: return False
    return True


def _val_3gp(d):
    if len(d) < 12 or d[4:8] != b"ftyp": return False
    brand = d[8:12]
    return brand in (b"3gp5", b"3gp6", b"3gp7", b"3ge6", b"3gg6",
                     b"3gs7", b"3g2a", b"3g2b", b"3g2c")


# ── Documents ────────────────────────────────────────────────────────

def _val_pdf(d):
    if len(d) < 20 or d[:4] != b"%PDF": return False
    # Version : %PDF-1.0 à %PDF-2.0 ou %PDF-1.x
    version_byte = d[5:8]
    valid_versions = {b"1.0", b"1.1", b"1.2", b"1.3", b"1.4",
                      b"1.5", b"1.6", b"1.7", b"2.0"}
    if version_byte not in valid_versions: return False
    return len(d) >= 100


def _val_zip(d):
    if len(d) < 30 or d[:4] != b"PK\x03\x04": return False
    ver_needed    = _u16le(d, 4)
    if ver_needed > 63: return False    # version > 6.3 = suspect
    compress      = _u16le(d, 8)
    if compress not in (0, 8, 9, 12, 14): return False  # stored/deflate/deflate64/bzip2/lzma
    fname_len     = _u16le(d, 26)
    extra_len     = _u16le(d, 28)
    if fname_len > 65535 or extra_len > 65535: return False
    return len(d) >= 30 + fname_len


def _val_ole2(d):
    if len(d) < 8 or d[:8] != b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1": return False
    if len(d) < 30: return False
    sector_power = _u16le(d, 30)
    return 7 <= sector_power <= 12     # 512B à 4096B par secteur


def _val_rtf(d):
    if len(d) < 20 or not d.startswith(b"{\\rtf1"): return False
    return any(c in d[:200] for c in (b"\\ansi", b"\\mac", b"\\pc",
                                       b"\\pca", b"\\deff", b"\\rtf"))


def _val_djvu(d):
    if len(d) < 16 or d[:8] != b"AT&TFORM": return False
    return d[12:16] in (b"DJVU", b"DJVM", b"DJVI", b"THUM")


def _val_mobi(d):
    if len(d) < 80: return False
    # PalmDOC header + MOBI header magic
    return d[60:68] == b"BOOKMOBI"


# ── Archives ─────────────────────────────────────────────────────────

def _val_rar4(d):
    return (len(d) >= 7 and
            d[:7] == b"Rar!\x1A\x07\x00")


def _val_rar5(d):
    return (len(d) >= 8 and
            d[:8] == b"Rar!\x1A\x07\x01\x00")


def _val_7z(d):
    if len(d) < 6 or d[:6] != b"7z\xBC\xAF'\x1C": return False
    major = _u8(d, 6)
    return major == 0


def _val_gzip(d):
    if len(d) < 18 or d[:2] != b"\x1F\x8B": return False
    if d[2] != 8: return False          # seule méthode valide = deflate
    flags = d[3]
    if flags & 0xE0: return False       # bits 5-7 réservés
    mtime = _u32le(d, 4)
    xfl   = d[8]
    os_   = d[9]
    if xfl not in (0, 2, 4): return False
    return True


def _val_bzip2(d):
    if len(d) < 10 or d[:2] != b"BZ": return False
    if d[2] != ord('h'): return False   # huffman
    if d[3] not in b"123456789": return False
    return d[4:10] == b"1AY&SY"        # block magic PI


def _val_xz(d):
    if len(d) < 12 or d[:6] != b"\xFD7zXZ\x00": return False
    if d[6] != 0: return False          # premier byte flags = 0
    check_type = d[7] & 0x0F
    if d[7] & 0xF0: return False        # bits hauts réservés
    return check_type <= 10


def _val_zstd(d):
    if len(d) < 5 or d[:4] != b"\x28\xB5\x2F\xFD": return False
    fhd = d[4]
    version = (fhd >> 6) & 0x3
    return version == 2                 # seule version valide


def _val_lz4(d):
    if len(d) < 7 or d[:4] != b"\x04\x22\x4D\x18": return False
    flg = d[4]
    if (flg >> 6) != 1: return False    # version doit être 01
    bd  = d[5]
    if bd & 0x8F: return False          # bits réservés
    bsz = (bd >> 4) & 0x7
    return bsz in (4, 5, 6, 7)         # 64KB à 4MB block size


def _val_lzma(d):
    if len(d) < 13: return False
    props = d[0]
    lc = props % 9
    props //= 9
    lp = props % 5
    pb = props // 5
    if pb > 4 or lp > 4 or lc > 8: return False  # propriétés invalides
    dict_size = _u32le(d, 1)
    return dict_size >= 4096


def _val_cab(d):
    if len(d) < 36 or d[:4] != b"MSCF": return False
    if _u32le(d, 4) != 0: return False    # réservé
    total_size = _u32le(d, 8)
    if total_size < 36: return False
    version_minor = _u8(d, 24)
    version_major = _u8(d, 25)
    return version_major in (1, 2, 3) and version_minor in (0, 3)


def _val_iso(d):
    # Primary Volume Descriptor à offset 16*2048 = 32768
    # Mais en raw carving on a le début du fichier
    # Vérifier signature à offset 1 (après le byte de type)
    if len(d) < 6: return False
    if d[1:6] == b"CD001": return True
    # Si on a assez de données, vérifier à l'offset 16*2048
    if len(d) >= 32774:
        return d[32769:32774] == b"CD001"
    return False


# ── Bases de données ─────────────────────────────────────────────────

def _val_sqlite(d):
    if len(d) < 100 or d[:16] != b"SQLite format 3\x00": return False
    page_size = _u16be(d, 16)
    if page_size not in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536): return False
    if _u8(d, 18) != 1 or _u8(d, 19) != 1: return False  # read/write version
    return True


def _val_registry(d):
    if len(d) < 4 or d[:4] != b"regf": return False
    if len(d) < 8: return True
    seq1 = _u32le(d, 4)
    seq2 = _u32le(d, 8) if len(d) >= 12 else seq1
    return seq1 <= 0x7FFFFFFF and seq2 <= 0x7FFFFFFF


def _val_ese(d):
    if len(d) < 20: return False
    if d[4:16] != b"Standard J": return False
    version = _u32le(d, 0)
    return version in (0, 1)


# ── Forensics Windows ────────────────────────────────────────────────

def _val_evtx(d):
    if len(d) < 24 or d[:8] != b"ElfFile\x00": return False
    version_major = _u16le(d, 20)
    version_minor = _u16le(d, 22)
    return version_major in (3, 4) and version_minor in (0, 1)


def _val_prefetch(d):
    if len(d) < 8 or d[:4] != b"SCCA": return False
    version = _u32le(d, 4) if len(d) >= 8 else 0
    return version in (17, 23, 26, 30)     # XP, Vista/7, 8, 10


def _val_lnk(d):
    if len(d) < 20: return False
    if d[:4] != b"\x4C\x00\x00\x00": return False
    # GUID du shell link: 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46
    lnk_guid = b"\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46"
    return d[4:20] == lnk_guid


def _val_mft(d):
    if len(d) < 8 or d[:4] != b"FILE": return False
    fixup_offset = _u16le(d, 4)
    fixup_count  = _u16le(d, 6)
    return 2 <= fixup_offset <= 56 and 1 <= fixup_count <= 32


# ── Exécutables ──────────────────────────────────────────────────────

def _val_elf(d):
    if len(d) < 16 or d[:4] != b"\x7FELF": return False
    ei_class = d[4]
    if ei_class not in (1, 2): return False    # 32-bit ou 64-bit
    ei_data  = d[5]
    if ei_data  not in (1, 2): return False    # LE ou BE
    ei_ver   = d[6]
    if ei_ver != 1: return False
    if len(d) < 18: return True
    e_type = _u16le(d, 16) if ei_data == 1 else _u16be(d, 16)
    return e_type in (1, 2, 3, 4)             # REL, EXEC, DYN, CORE


def _val_pe(d):
    if len(d) < 64 or d[:2] != b"MZ": return False
    e_lfanew = _u32le(d, 60)
    if e_lfanew < 64 or e_lfanew > 0x10000: return False
    if e_lfanew + 4 > len(d): return True     # données tronquées mais MZ+e_lfanew valide
    return d[e_lfanew:e_lfanew+4] == b"PE\x00\x00"


def _val_dex(d):
    if len(d) < 8 or d[:3] != b"dex": return False
    if d[3] != 0x0A: return False
    ver = d[4:7]
    return ver in (b"035", b"036", b"037", b"038", b"039")


def _val_macho(d):
    if len(d) < 8: return False
    magic = _u32le(d, 0)
    if magic in (0xFEEDFACE, 0xFEEDFACF):     # native Mach-O
        cputype = _u32le(d, 4) & 0x00FFFFFF
        return cputype in (7, 12, 14, 18)     # x86, ARM, SPARC, PPC
    if magic in (0xCEFAEDFE, 0xCFFAEDFE):     # byte-swapped
        return True
    return False


def _val_macho_fat(d):
    if len(d) < 8 or d[:4] != b"\xCA\xFE\xBA\xBE": return False
    narch = _u32be(d, 4)
    return 1 <= narch <= 20


def _val_java_class(d):
    if len(d) < 8 or d[:4] != b"\xCA\xFE\xBA\xBE": return False
    nfat = _u32be(d, 4)
    if nfat <= 20: return False            # probablement Mach-O FAT
    major = _u16be(d, 6)
    return 44 <= major <= 70              # Java 1.0 (44) → Java 26 (70)


def _val_wasm(d):
    if len(d) < 8 or d[:4] != b"\x00asm": return False
    version = _u32le(d, 4)
    return version == 1


# ── Crypto / Sécurité ────────────────────────────────────────────────

def _val_pem(d):
    if len(d) < 30 or not d.startswith(b"-----BEGIN"): return False
    end_idx = d.find(b"-----END", 0, len(d))
    return end_idx != -1


def _val_pkcs12(d):
    if len(d) < 4 or d[:2] != b"\x30\x82": return False
    # Outer SEQUENCE length
    outer_len = _u16be(d, 2)
    return 4 <= outer_len <= 0x10000 and len(d) >= 10


def _val_gpg(d):
    if len(d) < 6: return False
    # New-format packet tag: bit 7=1, bit 6=1
    if (d[0] & 0xC0) == 0xC0: return True
    # Old-format packet: bit 7=1, bit 6=0
    if (d[0] & 0xC0) == 0x80:
        tag = (d[0] >> 2) & 0xF
        return tag in (2, 5, 6, 13, 14)   # signature, secret key, public key, user ID, sub key
    return False


def _val_keepass(d):
    if len(d) < 12 or d[:4] != b"\x03\xD9\xA2\x9A": return False
    if d[4:8] != b"\x67\xFB\x4B\xB5": return False
    version_minor = _u16le(d, 8)
    version_major = _u16le(d, 10)
    return version_major in (1, 3) and version_minor <= 10


def _val_luks(d):
    if len(d) < 8 or d[:6] != b"LUKS\xBA\xBE": return False
    version = _u16be(d, 6)
    return version in (1, 2)


# ── Email / PIM ──────────────────────────────────────────────────────

def _val_eml(d):
    if len(d) < 30 or d[:5] != b"From ": return False
    first_newline = d.find(b"\n", 5)
    if first_newline == -1: first_newline = 80
    first_line = d[5:first_newline]
    # Format mbox: "From user@host date" → chercher @
    if b"@" in first_line: return True
    # MIME email peut commencer par "From " sans @
    return b"Date:" in d[:200] or b"MIME" in d[:200]


def _val_pst(d):
    if len(d) < 8 or d[:4] != b"!BDN": return False
    magic = _u32le(d, 4)
    return magic in (0x4E444221, 0x4E444223, 0x4E444226, 0x4E444233)


def _val_vcard(d):
    if len(d) < 20 or not d.startswith(b"BEGIN:VCARD"): return False
    return b"VERSION" in d[:100] or b"END:VCARD" in d


def _val_ical(d):
    if len(d) < 30 or not d.startswith(b"BEGIN:VCALENDAR"): return False
    return b"VERSION" in d[:200] or b"END:VCALENDAR" in d


# ── Divers ───────────────────────────────────────────────────────────

def _val_pcap(d):
    if len(d) < 24: return False
    magic = _u32le(d, 0)
    if magic not in (0xD4C3B2A1, 0xA1B2C3D4): return False
    major = _u16le(d, 4) if magic == 0xD4C3B2A1 else _u16be(d, 4)
    minor = _u16le(d, 6) if magic == 0xD4C3B2A1 else _u16be(d, 6)
    return major == 2 and minor == 4


def _val_pcapng(d):
    if len(d) < 12 or d[:4] != b"\x0A\x0D\x0D\x0A": return False
    # Section Header Block type = 0x0A0D0D0A
    # Byte-order magic à offset 8
    bom = _u32le(d, 8)
    return bom in (0x1A2B3C4D, 0x4D3C2B1A)


def _val_xml(d):
    if len(d) < 20 or d[:5] != b"<?xml": return False
    return b"version" in d[:100]


def _val_html(d):
    head = d[:20].lower() if len(d) >= 20 else d.lower()
    if not head.startswith(b"<!doctype"): return False
    return b"html" in d[:100].lower()


def _val_html2(d):
    if len(d) < 20: return False
    head = d[:20].lower()
    if not head.startswith(b"<html"): return False
    return b">" in d[:200]


def _val_torrent(d):
    if len(d) < 20 or not d.startswith(b"d8:announce"): return False
    return b"info" in d[:500]


def _val_vmdk(d):
    return len(d) >= 4 and d[:4] == b"KDMV"


def _val_qcow2(d):
    if len(d) < 8 or d[:4] != b"QFI\xFB": return False
    version = _u32be(d, 4)
    return version in (2, 3)


def _val_font_ttf(d):
    if len(d) < 12 or d[:5] != b"\x00\x01\x00\x00\x00": return False
    ntables = _u16be(d, 4)
    return 4 <= ntables <= 40


def _val_font_otf(d):
    if len(d) < 12 or d[:4] != b"OTTO": return False
    ntables = _u16be(d, 4)
    return 4 <= ntables <= 40


def _val_font_woff(d):
    if len(d) < 44 or d[:4] != b"wOFF": return False
    flavor = _u32be(d, 4)
    return flavor in (0x00010000, 0x4F54544F)  # TrueType ou CFF


def _val_bplist(d):
    if len(d) < 8 or d[:6] != b"bplist": return False
    version = d[6:8]
    return version in (b"00", b"01", b"14", b"15", b"16")


def _val_android_sparse(d):
    if len(d) < 28 or d[:4] != b"\x3A\xFF\x26\xED": return False
    major_ver = _u16le(d, 4)
    return major_ver == 1


def _val_crc3(d):
    # CR3 (Canon RAW v3) : ftyp avec brand "crx "
    if len(d) < 12 or d[4:8] != b"ftyp": return False
    return d[8:12] == b"crx "


def _val_crx(d):
    if len(d) < 12 or d[:4] != b"Cr24": return False
    version = _u32le(d, 4)
    return version in (2, 3)


# ════════════════════════════════════════════════════════════════════
# SIGNATURES
# ════════════════════════════════════════════════════════════════════

SIGNATURES: list = [

    # ── Images raster ────────────────────────────────────────────────
    SigDef("JPEG",      ".jpg",  b"\xFF\xD8\xFF",
           b"\xFF\xD9", 50*_MB,  min_size=100,
           validator=_val_jpeg,  category="image", description="Image JPEG"),

    SigDef("PNG",       ".png",  b"\x89PNG\r\n\x1a\n",
           b"\x00\x00\x00\x00IEND\xaeB`\x82", 200*_MB, min_size=45,
           validator=_val_png,   category="image", description="Image PNG"),

    SigDef("GIF87",     ".gif",  b"GIF87a", b"\x00;", 20*_MB, min_size=35,
           validator=_val_gif,   category="image"),

    SigDef("GIF89",     ".gif",  b"GIF89a", b"\x00;", 20*_MB, min_size=35,
           validator=_val_gif,   category="image"),

    SigDef("BMP",       ".bmp",  b"BM", None, 200*_MB, min_size=26,
           validator=_val_bmp,   category="image", description="Image Bitmap"),

    SigDef("TIFF-LE",   ".tif",  b"II\x2A\x00", None, 500*_MB, min_size=100,
           validator=_val_tiff_le, category="image", description="TIFF Little-Endian"),

    SigDef("TIFF-BE",   ".tif",  b"MM\x00\x2A", None, 500*_MB, min_size=100,
           validator=_val_tiff_be, category="image", description="TIFF Big-Endian"),

    SigDef("WebP",      ".webp", b"RIFF",   None, 50*_MB,  min_size=30,
           validator=_val_webp,  category="image", description="Image WebP"),

    SigDef("PSD",       ".psd",  b"8BPS",   None, 2*_GB,   min_size=26,
           validator=_val_psd,   category="image", description="Adobe Photoshop"),

    SigDef("ICO",       ".ico",  b"\x00\x00\x01\x00", None, 4*_MB, min_size=22,
           validator=_val_ico,   category="image", description="Icône Windows"),

    SigDef("CR2",       ".cr2",  b"II\x2A\x00\x10\x00\x00\x00CR", None, 100*_MB, min_size=200,
           validator=_val_cr2,   category="image", description="RAW Canon CR2"),

    SigDef("CR3",       ".cr3",  b"\x00\x00\x00\x18ftypcrx ", None, 200*_MB, min_size=200,
           validator=_val_crc3,  category="image", description="RAW Canon CR3"),

    SigDef("NEF",       ".nef",  b"MM\x00\x2A\x00\x00\x00\x08", None, 100*_MB, min_size=200,
           validator=_val_tiff_be, category="image", description="RAW Nikon NEF"),

    SigDef("DNG",       ".dng",  b"II\x2A\x00\x08\x00\x00\x00", None, 100*_MB, min_size=200,
           validator=_val_tiff_le, category="image", description="RAW Adobe DNG"),

    # HEIC / HEIF
    SigDef("HEIC",      ".heic", b"\x00\x00\x00\x18ftypheic", None, 200*_MB, min_size=200,
           validator=_val_heic,  category="image", description="Image HEIC/HEIF (Apple)"),
    SigDef("HEIC2",     ".heic", b"\x00\x00\x00\x1Cftypheic", None, 200*_MB, min_size=200,
           validator=_val_heic,  category="image"),
    SigDef("MIF1",      ".heif", b"\x00\x00\x00\x18ftypmif1", None, 200*_MB, min_size=200,
           validator=_val_heic,  category="image", description="Image HEIF"),

    # AVIF
    SigDef("AVIF",      ".avif", b"\x00\x00\x00\x1Cftypavif", None, 200*_MB, min_size=200,
           validator=_val_avif,  category="image", description="Image AVIF (AV1)"),
    SigDef("AVIF2",     ".avif", b"\x00\x00\x00\x18ftypavif", None, 200*_MB, min_size=200,
           validator=_val_avif,  category="image"),

    # JPEG XL (container seulement — magic 12 bytes distinctif)
    SigDef("JXL-Box",   ".jxl",  b"\x00\x00\x00\x0CJXLa", None, 200*_MB, min_size=64,
           validator=_val_jxl,   category="image", description="JPEG XL container"),

    # ── Vidéo ─────────────────────────────────────────────────────────
    SigDef("MP4",       ".mp4",  b"\x00\x00\x00\x18ftyp", None, 4*_GB, min_size=512,
           validator=_val_mp4,   category="video"),
    SigDef("MP4v2",     ".mp4",  b"\x00\x00\x00\x1Cftyp", None, 4*_GB, min_size=512,
           validator=_val_mp4,   category="video"),
    SigDef("MP4v3",     ".mp4",  b"\x00\x00\x00\x20ftyp", None, 4*_GB, min_size=512,
           validator=_val_mp4,   category="video"),
    SigDef("MP4v4",     ".mp4",  b"\x00\x00\x00\x14ftyp", None, 4*_GB, min_size=512,
           validator=_val_mp4,   category="video"),
    SigDef("M4V",       ".m4v",  b"\x00\x00\x00\x1CftypM4V", None, 4*_GB, min_size=512,
           validator=_val_mp4,   category="video"),
    SigDef("MOV",       ".mov",  b"\x00\x00\x00\x14ftypqt  ", None, 4*_GB, min_size=512,
           validator=_val_mp4,   category="video", description="QuickTime MOV"),
    SigDef("3GP",       ".3gp",  b"\x00\x00\x00\x14ftyp3gp", None, 500*_MB, min_size=512,
           validator=_val_3gp,   category="video"),
    SigDef("AVI",       ".avi",  b"RIFF",     None, 4*_GB,  min_size=64,
           validator=_val_avi,   category="video"),
    SigDef("MKV",       ".mkv",  b"\x1A\x45\xDF\xA3", None, 4*_GB, min_size=256,
           validator=_val_mkv_webm, category="video"),
    SigDef("WebM",      ".webm", b"\x1A\x45\xDF\xA3", None, 4*_GB, min_size=256,
           validator=_val_mkv_webm, category="video"),
    SigDef("FLV",       ".flv",  b"FLV\x01", None, 2*_GB,  min_size=9,
           validator=_val_flv,   category="video", description="Flash Video"),
    SigDef("WMV",       ".wmv",  b"\x30\x26\xB2\x75\x8E\x66\xCF\x11"
                                  b"\xA6\xD9\x00\xAA\x00\x62\xCE\x6C",
           None, 2*_GB, min_size=30,
           validator=_val_wma_wmv, category="video", description="Windows Media Video"),
    SigDef("MPEG",      ".mpg",  b"\x00\x00\x01\xBA", None, 4*_GB, min_size=12,
           validator=_val_mpeg_ps, category="video", description="MPEG-1/2 Program Stream"),
    SigDef("MPEG-ES",   ".mpg",  b"\x00\x00\x01\xB3", None, 4*_GB, min_size=12,
           validator=_val_mpeg_es, category="video", description="MPEG Elementary Stream"),
    SigDef("TS",        ".ts",   b"\x47\x40\x00\x10", None, 4*_GB, min_size=188,
           validator=_val_ts,    category="video", description="MPEG Transport Stream"),

    # ── Audio ─────────────────────────────────────────────────────────
    SigDef("MP3-ID3",   ".mp3",  b"ID3",     None, 200*_MB, min_size=100,
           validator=_val_mp3_id3, category="audio"),
    SigDef("MP3",       ".mp3",  b"\xFF\xFB", None, 100*_MB, min_size=256,
           validator=_val_mp3_sync, category="audio"),
    SigDef("MP3-2",     ".mp3",  b"\xFF\xFA", None, 100*_MB, min_size=256,
           validator=_val_mp3_sync, category="audio"),
    SigDef("OGG",       ".ogg",  b"OggS",    None, 500*_MB, min_size=50,
           validator=_val_ogg,   category="audio"),
    SigDef("FLAC",      ".flac", b"fLaC",    None, 2*_GB,  min_size=42,
           validator=_val_flac,  category="audio"),
    SigDef("WAV",       ".wav",  b"RIFF",    None, 2*_GB,  min_size=44,
           validator=_val_wav,   category="audio"),
    SigDef("AAC-ADTS",  ".aac",  b"\xFF\xF1", None, 50*_MB, min_size=128,
           validator=_val_aac,   category="audio"),
    SigDef("AAC-ADTS2", ".aac",  b"\xFF\xF9", None, 50*_MB, min_size=128,
           validator=_val_aac,   category="audio"),
    SigDef("M4A",       ".m4a",  b"\x00\x00\x00\x1CftypM4A ", None, 500*_MB, min_size=512,
           validator=_val_m4a,   category="audio"),
    SigDef("WMA",       ".wma",  b"\x30\x26\xB2\x75\x8E\x66\xCF\x11"
                                  b"\xA6\xD9\x00\xAA\x00\x62\xCE\x6C",
           None, 500*_MB, min_size=30,
           validator=_val_wma_wmv, category="audio", description="Windows Media Audio"),
    SigDef("AIFF",      ".aif",  b"FORM",    None, 500*_MB, min_size=12,
           validator=_val_aiff,  category="audio"),
    SigDef("APE",       ".ape",  b"MAC ",    None, 2*_GB,  min_size=100,
           category="audio",     description="Monkey Audio APE"),

    # ── Documents ─────────────────────────────────────────────────────
    SigDef("PDF",       ".pdf",  b"%PDF-",   b"%%EOF", 500*_MB, min_size=100,
           validator=_val_pdf,   category="document"),
    SigDef("ZIP-Office",".zip",  b"PK\x03\x04", b"PK\x05\x06", 2*_GB, min_size=30,
           validator=_val_zip,   category="document",
           description="ZIP / DOCX / XLSX / PPTX / ODT / EPUB / APK / JAR"),
    SigDef("DOC-OLE",   ".doc",  b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", None, 500*_MB, min_size=512,
           validator=_val_ole2,  category="document", description="MS Office ancien OLE2"),
    SigDef("RTF",       ".rtf",  b"{\\rtf1", None, 100*_MB, min_size=20,
           validator=_val_rtf,   category="document"),
    SigDef("DjVu",      ".djvu", b"AT&TFORM", None, 200*_MB, min_size=16,
           validator=_val_djvu,  category="document"),
    SigDef("CHM",       ".chm",  b"ITSF\x03\x00\x00\x00", None, 200*_MB, min_size=50,
           category="document",  description="Microsoft Help CHM"),
    SigDef("MOBI",      ".mobi", b"BOOKMOBI", None, 200*_MB, min_size=80,
           validator=_val_mobi,  category="document"),

    # ── Archives ──────────────────────────────────────────────────────
    SigDef("RAR4",      ".rar",  b"Rar!\x1A\x07\x00", None, 4*_GB, min_size=20,
           validator=_val_rar4,  category="archive"),
    SigDef("RAR5",      ".rar",  b"Rar!\x1A\x07\x01\x00", None, 4*_GB, min_size=20,
           validator=_val_rar5,  category="archive"),
    SigDef("7Z",        ".7z",   b"7z\xBC\xAF'\x1C", None, 4*_GB, min_size=32,
           validator=_val_7z,    category="archive"),
    SigDef("GZIP",      ".gz",   b"\x1F\x8B", None, 4*_GB,  min_size=18,
           validator=_val_gzip,  category="archive"),
    SigDef("BZIP2",     ".bz2",  b"BZh",      None, 2*_GB,  min_size=10,
           validator=_val_bzip2, category="archive"),
    SigDef("XZ",        ".xz",   b"\xFD7zXZ\x00", None, 4*_GB, min_size=32,
           validator=_val_xz,    category="archive"),
    SigDef("ZSTD",      ".zst",  b"\x28\xB5\x2F\xFD", None, 4*_GB, min_size=10,
           validator=_val_zstd,  category="archive", description="Zstandard"),
    SigDef("LZ4",       ".lz4",  b"\x04\x22\x4D\x18", None, 4*_GB, min_size=11,
           validator=_val_lz4,   category="archive"),
    SigDef("LZMA",      ".lzma", b"\x5D\x00\x00", None, 4*_GB, min_size=13,
           validator=_val_lzma,  category="archive"),
    SigDef("TAR",       ".tar",  b"ustar",    None, 4*_GB,  min_size=512,
           category="archive"),
    SigDef("CAB",       ".cab",  b"MSCF\x00\x00\x00\x00", None, 2*_GB, min_size=36,
           validator=_val_cab,   category="archive", description="Cabinet Windows"),
    SigDef("ISO",       ".iso",  b"CD001",    None, 8*_GB,  min_size=40960,
           validator=_val_iso,   category="archive", description="Image ISO 9660"),
    SigDef("DMG",       ".dmg",  b"koly",     None, 8*_GB,  min_size=512,
           category="archive",   description="Image disque macOS"),

    # ── Bases de données ──────────────────────────────────────────────
    SigDef("SQLite",    ".db",   b"SQLite format 3\x00", None, 2*_GB, min_size=100,
           validator=_val_sqlite, category="database",
           description="SQLite — WhatsApp, iOS, navigateurs"),
    SigDef("Registry",  ".dat",  b"regf", None, 200*_MB, min_size=4096,
           validator=_val_registry, category="database",
           description="Ruche de registre Windows"),
    SigDef("ESE-DB",    ".edb",  b"\x00\x01\x00\x00Standard J", None, 4*_GB, min_size=4096,
           validator=_val_ese,   category="database",
           description="ESE/JET — NTDS.dit, IE history, SRUM"),
    SigDef("LevelDB-Log",".log", b"\xef\xbf\xbd\xef\xbf\xbd", None, 100*_MB, min_size=32,
           category="database",  description="LevelDB — Chrome, WhatsApp"),

    # ── Forensics Windows ─────────────────────────────────────────────
    SigDef("EVTX",      ".evtx", b"ElfFile\x00", None, 200*_MB, min_size=4096,
           validator=_val_evtx,  category="forensics",
           description="Windows Event Log"),
    SigDef("Prefetch",  ".pf",   b"SCCA", None, 2*_MB,  min_size=200,
           validator=_val_prefetch, category="forensics",
           description="Windows Prefetch"),
    SigDef("LNK",       ".lnk",  b"\x4C\x00\x00\x00\x01\x14\x02\x00", None, 4*_MB, min_size=76,
           validator=_val_lnk,   category="forensics",
           description="Windows Shortcut LNK"),
    SigDef("MFT-Record",".mft",  b"FILE\x00\x00\x00\x00", None, 4*_KB, min_size=48,
           validator=_val_mft,   category="forensics",
           description="Enregistrement MFT NTFS"),
    SigDef("EVTX-Rec",  ".evtx", b"\x2A\x2A\x00\x00", None, 512*_KB, min_size=24,
           category="forensics", description="Record EVTX individuel"),
    SigDef("Thumbs",    ".db",   b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", None, 50*_MB, min_size=512,
           validator=_val_ole2,  category="forensics",
           description="Thumbs.db miniatures Windows"),

    # ── Exécutables ───────────────────────────────────────────────────
    SigDef("ELF",       "",      b"\x7FELF", None, 2*_GB,  min_size=64,
           validator=_val_elf,   category="executable"),
    SigDef("PE",        ".exe",  b"MZ",      None, 500*_MB, min_size=64,
           validator=_val_pe,    category="executable"),
    SigDef("DEX",       ".dex",  b"dex\n035\x00", None, 100*_MB, min_size=112,
           validator=_val_dex,   category="executable",
           description="Bytecode Android DEX"),
    SigDef("DEX2",      ".dex",  b"dex\n036\x00", None, 100*_MB, min_size=112,
           validator=_val_dex,   category="executable"),
    SigDef("DEX3",      ".dex",  b"dex\n038\x00", None, 100*_MB, min_size=112,
           validator=_val_dex,   category="executable"),
    SigDef("MACHO-32",  "",      b"\xCE\xFA\xED\xFE", None, 200*_MB, min_size=28,
           validator=_val_macho, category="executable",
           description="Mach-O 32-bit"),
    SigDef("MACHO-64",  "",      b"\xCF\xFA\xED\xFE", None, 500*_MB, min_size=32,
           validator=_val_macho, category="executable",
           description="Mach-O 64-bit"),
    SigDef("MACHO-FAT", "",      b"\xCA\xFE\xBA\xBE", None, 500*_MB, min_size=8,
           validator=_val_macho_fat, category="executable",
           description="Mach-O Universal Binary"),
    SigDef("Java-Class",".class",b"\xCA\xFE\xBA\xBE", None, 50*_MB, min_size=8,
           validator=_val_java_class, category="executable",
           description="Java bytecode .class"),
    SigDef("WASM",      ".wasm", b"\x00asm", None, 100*_MB, min_size=8,
           validator=_val_wasm,  category="executable",
           description="WebAssembly"),
    SigDef("CRX",       ".crx",  b"Cr24",    None, 200*_MB, min_size=12,
           validator=_val_crx,   category="executable",
           description="Extension Chrome/Chromium"),

    # ── Crypto / Sécurité ─────────────────────────────────────────────
    SigDef("PEM",       ".pem",  b"-----BEGIN", None, 500*_KB, min_size=30,
           validator=_val_pem,   category="crypto"),
    SigDef("SSH-PRIV",  ".key",  b"-----BEGIN OPENSSH PRIVATE KEY-----",
           b"-----END OPENSSH PRIVATE KEY-----", 20*_KB, min_size=100,
           validator=_val_pem,   category="crypto",
           description="Clé privée SSH OpenSSH"),
    SigDef("PKCS12",    ".pfx",  b"\x30\x82", None, 50*_MB, min_size=10,
           validator=_val_pkcs12, category="crypto",
           description="Certificat PKCS#12/PFX"),
    SigDef("GPG",       ".gpg",  b"\x99\x01", None, 50*_MB, min_size=6,
           validator=_val_gpg,   category="crypto"),
    SigDef("KeePass",   ".kdbx", b"\x03\xD9\xA2\x9A\x67\xFB\x4B\xB5",
           None, 200*_MB, min_size=100,
           validator=_val_keepass, category="crypto",
           description="Base de mots de passe KeePass"),
    SigDef("Keystore",  ".bks",  b"\xFE\xED\xFE\xED", None, 50*_MB, min_size=16,
           category="crypto",    description="Android Keystore / JKS"),
    SigDef("LUKS",      ".luks", b"LUKS\xBA\xBE", None, 0, min_size=592,
           validator=_val_luks,  category="crypto",
           description="Volume chiffré LUKS"),
    SigDef("VeraCrypt", ".vc",   b"TRUE",    None, 0,  min_size=512,
           category="crypto",    description="Volume VeraCrypt"),

    # ── Emails / PIM ──────────────────────────────────────────────────
    SigDef("EML",       ".eml",  b"From ",   None, 50*_MB, min_size=200,
           validator=_val_eml,   category="email"),
    SigDef("MBOX",      ".mbox", b"From ",   None, 4*_GB,  min_size=500,
           validator=_val_eml,   category="email",
           description="Boîte mail MBOX"),
    SigDef("PST",       ".pst",  b"!BDN",    None, 50*_GB, min_size=64,
           validator=_val_pst,   category="email",
           description="Microsoft Outlook PST"),
    SigDef("OST",       ".ost",  b"!BDN",    None, 50*_GB, min_size=64,
           validator=_val_pst,   category="email",
           description="Microsoft Outlook OST"),
    SigDef("VCard",     ".vcf",  b"BEGIN:VCARD", b"END:VCARD", 500*_KB, min_size=30,
           validator=_val_vcard, category="email"),
    SigDef("iCal",      ".ics",  b"BEGIN:VCALENDAR", b"END:VCALENDAR",
           5*_MB, min_size=50,
           validator=_val_ical,  category="email"),

    # ── Formats mobiles ───────────────────────────────────────────────
    SigDef("Android-Backup",".ab", b"ANDROID BACKUP\n", None, 4*_GB, min_size=200,
           category="mobile",    description="Sauvegarde Android"),
    SigDef("Android-Sparse",".img", b"\x3A\xFF\x26\xED", None, 8*_GB, min_size=28,
           validator=_val_android_sparse, category="mobile",
           description="Image sparse Android"),
    SigDef("bplist",    ".plist", b"bplist", None, 100*_MB, min_size=8,
           validator=_val_bplist, category="mobile",
           description="Apple Binary Property List"),

    # ── Réseau / Captures ─────────────────────────────────────────────
    SigDef("PCAP",      ".pcap", b"\xD4\xC3\xB2\xA1", None, 4*_GB, min_size=24,
           validator=_val_pcap,  category="misc",
           description="Capture réseau PCAP"),
    SigDef("PCAPng",    ".pcapng", b"\x0A\x0D\x0D\x0A", None, 4*_GB, min_size=28,
           validator=_val_pcapng, category="misc",
           description="Capture réseau PCAPng"),

    # ── Images disque virtuelles ───────────────────────────────────────
    SigDef("VMDK",      ".vmdk", b"KDMV",    None, 0, min_size=512,
           validator=_val_vmdk,  category="misc",
           description="Image disque VMware"),
    SigDef("QCOW2",     ".qcow2", b"QFI\xFB", None, 0, min_size=72,
           validator=_val_qcow2, category="misc",
           description="Image disque QEMU"),
    SigDef("VDI",       ".vdi",  b"<<< Oracle VM VirtualBox Disk Image >>>",
           None, 0,  min_size=512,
           category="misc",      description="Image disque VirtualBox"),
    SigDef("VHDX",      ".vhdx", b"vhdxfile", None, 0, min_size=512,
           category="misc",      description="Image disque Hyper-V VHDX"),

    # ── Divers ────────────────────────────────────────────────────────
    SigDef("Torrent",   ".torrent", b"d8:announce", None, 2*_MB, min_size=50,
           validator=_val_torrent, category="misc"),
    SigDef("XML",       ".xml",  b"<?xml",   None, 100*_MB, min_size=20,
           validator=_val_xml,   category="misc"),
    SigDef("HTML",      ".html", b"<!DOCTYPE html", None, 50*_MB, min_size=30,
           validator=_val_html,  category="misc"),
    SigDef("HTML2",     ".html", b"<html",   None, 50*_MB, min_size=30,
           validator=_val_html2, category="misc"),
    SigDef("Subtitle",  ".srt",  b"1\r\n00:", None, 5*_MB, min_size=20,
           category="misc",      description="Sous-titres SRT"),
    SigDef("Font-TTF",  ".ttf",  b"\x00\x01\x00\x00\x00", None, 50*_MB, min_size=12,
           validator=_val_font_ttf, category="misc",
           description="Police TrueType"),
    SigDef("Font-OTF",  ".otf",  b"OTTO\x00", None, 50*_MB, min_size=12,
           validator=_val_font_otf, category="misc",
           description="Police OpenType"),
    SigDef("Font-WOFF", ".woff", b"wOFF",    None, 50*_MB, min_size=44,
           validator=_val_font_woff, category="misc",
           description="Police WOFF"),
]


# ── Index utilitaires ────────────────────────────────────────────────

SIG_BY_NAME     = {s.name.lower(): s for s in SIGNATURES}
SIG_BY_EXT      = {}
for s in SIGNATURES:
    ext = s.ext.lstrip(".")
    if ext:
        SIG_BY_EXT.setdefault(ext, []).append(s)

SIG_BY_CATEGORY = {}
for s in SIGNATURES:
    SIG_BY_CATEGORY.setdefault(s.category, []).append(s)

CATEGORIES = sorted(SIG_BY_CATEGORY.keys())


def get_signatures(types_filter: str | None = None) -> list:
    if not types_filter or types_filter.strip().lower() in ("", "all"):
        return SIGNATURES

    wanted = {t.strip().lower() for t in types_filter.split(",")}
    result, seen = [], set()

    for w in wanted:
        if w in SIG_BY_CATEGORY:
            for s in SIG_BY_CATEGORY[w]:
                if s.name not in seen:
                    result.append(s); seen.add(s.name)
        if w in SIG_BY_NAME:
            s = SIG_BY_NAME[w]
            if s.name not in seen:
                result.append(s); seen.add(s.name)
        if w in SIG_BY_EXT:
            for s in SIG_BY_EXT[w]:
                if s.name not in seen:
                    result.append(s); seen.add(s.name)

    return result


def list_signatures():
    print(f"\n  {'Nom':<18} {'Ext':<8} {'MinSz':>8} {'MaxSz':>10} {'Cat':<14} Description")
    print(f"  {'─'*18} {'─'*8} {'─'*8} {'─'*10} {'─'*14} {'─'*35}")
    for cat in CATEGORIES:
        for s in SIG_BY_CATEGORY[cat]:
            def _sz(n):
                if n == 0: return "∞"
                if n >= _GB: return f"{n//_GB}Go"
                if n >= _MB: return f"{n//_MB}Mo"
                if n >= _KB: return f"{n//_KB}Ko"
                return str(n)
            print(f"  {s.name:<18} {s.ext or '—':<8} {_sz(s.min_size):>8} "
                  f"{_sz(s.max_size):>10} {s.category:<14} "
                  f"{s.description[:35] if s.description else ''}")
    print(f"\n  Total : {len(SIGNATURES)} signatures\n")


if __name__ == "__main__":
    list_signatures()
