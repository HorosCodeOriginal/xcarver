#!/usr/bin/env python3
"""
fs_parser.py — Parseur de systèmes de fichiers pour récupération avancée.

Supporte :
  - FAT12/FAT16/FAT32 / exFAT
  - NTFS (MFT, $LogFile, $UsnJrnl)
  - ext2/ext3/ext4 (superblock, inode table, journal)

Pour chaque FS, on extrait :
  - Les entrées supprimées (dossiers + fichiers avec noms originaux)
  - Les clusters alloués aux fichiers supprimés
  - Les timestamps (création, modification, accès)
  - La liste des runs (fragments) pour reconstruction
"""

import os
import shutil
import struct
import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

# ── Types communs ────────────────────────────────────────────────

class FSType(Enum):
    UNKNOWN = "unknown"
    FAT12   = "fat12"
    FAT16   = "fat16"
    FAT32   = "fat32"
    EXFAT   = "exfat"
    NTFS    = "ntfs"
    EXT2    = "ext2"
    EXT3    = "ext3"
    EXT4     = "ext4"
    HFS_PLUS = "hfs+"
    APFS     = "apfs"
    F2FS     = "f2fs"
    YAFFS2   = "yaffs2"
    BTRFS    = "btrfs"

@dataclass
class DeletedEntry:
    """Entrée de fichier supprimé récupérée depuis le FS."""
    name:         str
    size:         int
    fs_type:      FSType
    first_cluster: int         # FAT : premier cluster ; NTFS : premier VCN
    runs:         list[tuple]  # [(offset_bytes, length_bytes), ...]
    mtime:        Optional[datetime.datetime] = None
    ctime:        Optional[datetime.datetime] = None
    atime:        Optional[datetime.datetime] = None
    is_dir:       bool = False
    path:         str  = ""
    sha256:       str  = ""
    recovered_to: str  = ""

@dataclass
class FSInfo:
    fs_type:      FSType
    sector_size:  int
    cluster_size: int
    total_size:   int
    label:        str = ""
    entries:      list[DeletedEntry] = field(default_factory=list)

# ════════════════════════════════════════════════════════════════════
# DÉTECTION DU SYSTÈME DE FICHIERS
# ════════════════════════════════════════════════════════════════════

def detect_fs(reader) -> FSType:
    """
    Lit les premiers secteurs et identifie le FS.
    reader : objet avec méthode read_at(offset, length)

    Ordre de détection :
      1. APFS  — magic à boot[32]  (avant toute lecture du BPB)
      2. exFAT — OEM string à boot[3]
      3. NTFS  — OEM string à boot[3]
      4. FAT12/16 — type string à boot[54]
      5. FAT32 — type string à boot[82]
      6. ext2/3/4 — superblock à 1024 (magic 0xEF53)
      7. HFS+  — volume header à 1024
      8. F2FS  — superblock à 1024 (magic 0xF2F52010)
      9. Btrfs — superblock à 65536+64
      10. FAT heuristique OEM
      11. YAFFS2 heuristique
    """
    try:
        boot = reader.read_at(0, 512)
    except Exception:
        return FSType.UNKNOWN
    if len(boot) < 64:
        return FSType.UNKNOWN

    # ── APFS (Container Superblock — magic NXSB à offset 32) ──────
    try:
        apfs_magic = struct.unpack_from("<I", boot, 32)[0]
        if apfs_magic == 0x4253584E:  # 'NXSB'
            return FSType.APFS
    except Exception:
        pass

    # ── exFAT (OEM à boot[3:11]) ──────────────────────────────────
    if boot[3:11] == b"EXFAT   ":
        return FSType.EXFAT

    # ── NTFS  ─────────────────────────────────────────────────────
    if boot[3:11] == b"NTFS    ":
        return FSType.NTFS

    # ── FAT12/16 (type string au BPB étendu FAT16) ────────────────
    if len(boot) >= 62:
        fat_str = boot[54:59]
        if fat_str == b"FAT12":
            return FSType.FAT12
        if fat_str == b"FAT16":
            return FSType.FAT16

    # ── FAT32 (type string au BPB étendu FAT32) ───────────────────
    if len(boot) >= 90 and boot[82:87] == b"FAT32":
        return FSType.FAT32

    # ── ext2/3/4 (superblock à 1024, magic 0xEF53 à +56) ─────────
    try:
        sb = reader.read_at(1024, 100)
        if len(sb) >= 58:
            magic = struct.unpack_from("<H", sb, 56)[0]
            if magic == 0xEF53:
                feat = struct.unpack_from("<I", sb, 96)[0] if len(sb) >= 100 else 0
                if feat & 0x4:   return FSType.EXT4
                elif feat & 0x1: return FSType.EXT3
                else:            return FSType.EXT2
    except Exception:
        pass

    # ── HFS+ (Volume Header à 1024, magic 0x482B ou 0x4858) ──────
    try:
        hfs_raw = reader.read_at(1024, 2)
        hfs_magic = struct.unpack_from(">H", hfs_raw, 0)[0]
        if hfs_magic in (0x482B, 0x4858):   # 'H+' ou 'HX'
            return FSType.HFS_PLUS
    except Exception:
        pass

    # ── F2FS (superblock à 1024, magic 0xF2F52010) ───────────────
    try:
        f2fs_raw = reader.read_at(1024, 4)
        if struct.unpack_from("<I", f2fs_raw, 0)[0] == 0xF2F52010:
            return FSType.F2FS
    except Exception:
        pass

    # ── Btrfs (superblock à 65536+64, magic '_BHRfS_M') ──────────
    try:
        btrfs_raw = reader.read_at(65536 + 64, 8)
        if struct.unpack_from("<Q", btrfs_raw, 0)[0] == 0x4D5F53665248425F:
            return FSType.BTRFS
    except Exception:
        pass

    # ── FAT heuristique via OEM string ────────────────────────────
    oem = boot[3:11]
    if oem in (b"MSDOS5.0", b"MSWIN4.1", b"mkfs.fat"):
        try:
            sects_per_fat32 = struct.unpack_from("<I", boot, 36)[0]
            return FSType.FAT32 if sects_per_fat32 > 0 else FSType.FAT16
        except Exception:
            pass

    # ── YAFFS2 heuristique (OOB seq_number) ───────────────────────
    try:
        chunk = reader.read_at(2048, 64)
        if len(chunk) >= 8:
            oid = struct.unpack_from("<I", chunk, 0)[0]
            seq = struct.unpack_from("<I", chunk, 4)[0]
            if 0 < oid < 0xFFFE and 0 < seq < 0xFFFFFFFF:
                return FSType.YAFFS2
    except Exception:
        pass

    return FSType.UNKNOWN

# ════════════════════════════════════════════════════════════════════
# PARSEUR FAT32 / FAT16 / FAT12
# ════════════════════════════════════════════════════════════════════

def _fat_date(d, t):
    """Convertit date/heure FAT en datetime."""
    try:
        year  = ((d >> 9) & 0x7F) + 1980
        month = (d >> 5) & 0xF
        day   = d & 0x1F
        hour  = (t >> 11) & 0x1F
        minute= (t >> 5) & 0x3F
        sec   = (t & 0x1F) * 2
        return datetime.datetime(year, max(1,month), max(1,day), hour, minute, min(59,sec))
    except:
        return None

class FAT32Parser:
    def __init__(self, reader, fs_type: FSType):
        self.reader  = reader
        self.fs_type = fs_type
        self._parse_boot()

    def _parse_boot(self):
        boot = self.reader.read_at(0, 512)
        self.bytes_per_sector  = struct.unpack_from("<H", boot, 11)[0] or 512
        self.sects_per_cluster = boot[13] or 1
        self.reserved_sectors  = struct.unpack_from("<H", boot, 14)[0]
        self.num_fats          = boot[16] or 2
        self.root_entry_count  = struct.unpack_from("<H", boot, 17)[0]  # FAT16
        total_sectors16        = struct.unpack_from("<H", boot, 19)[0]
        self.total_sectors     = struct.unpack_from("<I", boot, 32)[0] or total_sectors16

        if self.fs_type in (FSType.FAT32, FSType.EXFAT):
            self.sects_per_fat = struct.unpack_from("<I", boot, 36)[0]
            self.root_cluster  = struct.unpack_from("<I", boot, 44)[0]
        else:
            self.sects_per_fat = struct.unpack_from("<H", boot, 22)[0]
            self.root_cluster  = 0

        self.cluster_size = self.bytes_per_sector * self.sects_per_cluster
        self.fat_offset   = self.reserved_sectors * self.bytes_per_sector
        self.data_offset  = (self.reserved_sectors +
                             self.num_fats * self.sects_per_fat) * self.bytes_per_sector

        if self.fs_type in (FSType.FAT32,):
            self.root_offset = self._cluster_offset(self.root_cluster)
        else:
            # FAT16 : root directory fixe avant data area
            self.root_offset = self.data_offset
            self.data_offset += self.root_entry_count * 32

    def _cluster_offset(self, cluster: int) -> int:
        return self.data_offset + (cluster - 2) * self.cluster_size

    def _read_fat_entry(self, cluster: int) -> int:
        """Lit la valeur FAT pour un cluster donné."""
        if self.fs_type == FSType.FAT32:
            off = self.fat_offset + cluster * 4
            raw = self.reader.read_at(off, 4)
            return struct.unpack_from("<I", raw)[0] & 0x0FFFFFFF
        elif self.fs_type == FSType.FAT16:
            off = self.fat_offset + cluster * 2
            raw = self.reader.read_at(off, 2)
            return struct.unpack_from("<H", raw)[0]
        else:  # FAT12
            off = self.fat_offset + (cluster * 3) // 2
            raw = self.reader.read_at(off, 2)
            val = struct.unpack_from("<H", raw)[0]
            return (val >> 4) if (cluster & 1) else (val & 0x0FFF)

    def _follow_chain(self, first_cluster: int) -> list[tuple]:
        """
        Suit la chaîne FAT depuis first_cluster.
        Retourne [(offset_bytes, size_bytes), ...] (runs)
        """
        runs = []
        visited = set()
        cluster = first_cluster
        eoc = {0x0FFFFFF8, 0xFFF8, 0xFF8}  # end-of-chain markers

        while cluster >= 2 and cluster not in visited:
            if self.fs_type == FSType.FAT32 and cluster >= 0x0FFFFFF8: break
            if self.fs_type == FSType.FAT16 and cluster >= 0xFFF8:     break
            if self.fs_type == FSType.FAT12 and cluster >= 0xFF8:      break
            visited.add(cluster)
            off = self._cluster_offset(cluster)
            runs.append((off, self.cluster_size))
            try:
                cluster = self._read_fat_entry(cluster)
            except:
                break
        return runs

    def parse_deleted(self, path: str = "") -> list[DeletedEntry]:
        """Parcourt les entrées de répertoire et retourne les entrées supprimées."""
        entries = []
        self._scan_dir(self.root_offset, path or "/", entries, depth=0)
        return entries

    def _scan_dir(self, dir_offset: int, current_path: str,
                  entries: list, depth: int):
        if depth > 16:
            return
        lfn_parts = {}
        offset = dir_offset

        for _ in range(65536):
            try:
                raw = self.reader.read_at(offset, 32)
            except:
                break
            if not raw or len(raw) < 32:
                break

            first = raw[0]
            if first == 0x00:
                break  # fin du répertoire
            if first == 0xE5:
                # Entrée supprimée
                attr = raw[11]
                if attr == 0x0F:
                    offset += 32
                    continue  # LFN entry pour fichier supprimé → skip pour l'instant
                name_raw = raw[1:8].rstrip(b'\x20') + b'.' + raw[8:11].rstrip(b'\x20')
                name = name_raw.decode("latin-1","replace").strip(".")
                if not name:
                    offset += 32
                    continue

                size          = struct.unpack_from("<I", raw, 28)[0]
                wdate         = struct.unpack_from("<H", raw, 24)[0]
                wtime         = struct.unpack_from("<H", raw, 22)[0]
                cdate         = struct.unpack_from("<H", raw, 16)[0]
                ctime_raw     = struct.unpack_from("<H", raw, 14)[0]
                cluster_hi    = struct.unpack_from("<H", raw, 20)[0]
                cluster_lo    = struct.unpack_from("<H", raw, 26)[0]
                first_cluster = (cluster_hi << 16) | cluster_lo

                is_dir = bool(attr & 0x10)
                runs   = self._follow_chain(first_cluster) if first_cluster >= 2 else []

                entry = DeletedEntry(
                    name          = name,
                    size          = size,
                    fs_type       = self.fs_type,
                    first_cluster = first_cluster,
                    runs          = runs,
                    mtime         = _fat_date(wdate, wtime),
                    ctime         = _fat_date(cdate, ctime_raw),
                    is_dir        = is_dir,
                    path          = current_path + name,
                )
                entries.append(entry)

                # Récurser dans les sous-répertoires supprimés
                if is_dir and first_cluster >= 2 and depth < 8:
                    sub_off = self._cluster_offset(first_cluster)
                    self._scan_dir(sub_off, current_path + name + "/",
                                   entries, depth + 1)

            offset += 32

# ════════════════════════════════════════════════════════════════════
# PARSEUR NTFS
# ════════════════════════════════════════════════════════════════════

def _ntfs_time(raw: int) -> Optional[datetime.datetime]:
    """Convertit un timestamp NTFS (100ns depuis 1601-01-01) en datetime."""
    try:
        EPOCH_DIFF = 116444736000000000
        return datetime.datetime(1970,1,1) + datetime.timedelta(
            microseconds=(raw - EPOCH_DIFF) // 10)
    except:
        return None

class NTFSParser:
    def __init__(self, reader):
        self.reader = reader
        self._parse_boot()

    def _parse_boot(self):
        boot = self.reader.read_at(0, 512)
        self.bytes_per_sector  = struct.unpack_from("<H", boot, 11)[0] or 512
        self.sects_per_cluster = boot[13] or 8
        self.cluster_size      = self.bytes_per_sector * self.sects_per_cluster
        self.mft_lcn           = struct.unpack_from("<Q", boot, 48)[0]
        self.mft_offset        = self.mft_lcn * self.cluster_size
        raw_rec_size           = struct.unpack_from("<i", boot, 64)[0]
        self.record_size       = (2 ** (-raw_rec_size)) if raw_rec_size < 0 else (raw_rec_size * self.cluster_size)
        self.record_size       = int(self.record_size)

    def parse_deleted(self) -> list[DeletedEntry]:
        """Scan le $MFT et retourne les enregistrements de fichiers supprimés."""
        entries = []
        offset  = self.mft_offset
        rec_n   = 0

        while rec_n < 5_000_000:  # sécurité max
            try:
                raw = self.reader.read_at(offset, self.record_size)
            except:
                break
            if not raw or len(raw) < 48:
                break
            if raw[:4] != b"FILE":
                offset += self.record_size
                rec_n  += 1
                continue

            flags = struct.unpack_from("<H", raw, 22)[0]
            in_use = flags & 0x01
            is_dir = bool(flags & 0x02)

            if not in_use:  # Enregistrement supprimé
                entry = self._parse_mft_record(raw, is_dir)
                if entry:
                    entries.append(entry)

            offset += self.record_size
            rec_n  += 1
            if len(raw) < self.record_size:
                break

        return entries

    def _parse_mft_record(self, raw: bytes, is_dir: bool) -> Optional[DeletedEntry]:
        """Parse un enregistrement MFT et extrait nom, taille, runs."""
        try:
            attr_offset = struct.unpack_from("<H", raw, 20)[0]
        except:
            return None

        name  = ""
        size  = 0
        runs  = []
        mtime = ctime = atime = None

        pos = attr_offset
        while pos + 8 < len(raw):
            try:
                attr_type = struct.unpack_from("<I", raw, pos)[0]
                attr_len  = struct.unpack_from("<I", raw, pos+4)[0]
            except:
                break

            if attr_type == 0xFFFFFFFF:
                break
            if attr_len == 0 or pos + attr_len > len(raw):
                break

            # $FILE_NAME (0x30)
            if attr_type == 0x30:
                try:
                    non_res = raw[pos + 8]
                    content_off = struct.unpack_from("<H", raw, pos + 20)[0]
                    content = raw[pos + content_off:]
                    if len(content) >= 66:
                        fname_len  = content[64]
                        fname_type = content[65]
                        if fname_len > 0 and fname_type != 2:  # ignore DOS names
                            name = content[66:66 + fname_len*2].decode("utf-16-le","replace")
                        # Timestamps depuis $FILE_NAME
                        mtime = _ntfs_time(struct.unpack_from("<Q", content, 8)[0])
                        atime = _ntfs_time(struct.unpack_from("<Q", content, 0)[0])
                        ctime = _ntfs_time(struct.unpack_from("<Q", content, 16)[0])
                        size  = struct.unpack_from("<Q", content, 48)[0]
                except:
                    pass

            # $DATA (0x80) — extrait les runs
            elif attr_type == 0x80:
                try:
                    non_res = raw[pos + 8]
                    if non_res:
                        data_runs_off = struct.unpack_from("<H", raw, pos + 32)[0]
                        runs = self._decode_runs(raw[pos + data_runs_off:])
                        if size == 0:
                            size = struct.unpack_from("<Q", raw, pos + 48)[0]
                    else:
                        # Résident : données inline
                        data_off = struct.unpack_from("<H", raw, pos + 20)[0]
                        data_len = struct.unpack_from("<I", raw, pos + 16)[0]
                        runs = [(pos + data_off, data_len)]
                except:
                    pass

            pos += attr_len

        if not name:
            return None

        return DeletedEntry(
            name          = name,
            size          = size,
            fs_type       = FSType.NTFS,
            first_cluster = runs[0][0] // self.cluster_size if runs else 0,
            runs          = runs,
            mtime         = mtime,
            ctime         = ctime,
            atime         = atime,
            is_dir        = is_dir,
            path          = name,
        )

    def _decode_runs(self, data: bytes) -> list[tuple]:
        """Décode les data runs NTFS en liste (offset_bytes, length_bytes)."""
        runs   = []
        pos    = 0
        lcn    = 0  # LCN courant (absolu)

        while pos < len(data):
            header = data[pos]
            if header == 0x00:
                break
            pos += 1

            len_bytes = header & 0x0F
            off_bytes = (header >> 4) & 0x0F

            if pos + len_bytes + off_bytes > len(data):
                break

            length_raw = int.from_bytes(data[pos:pos+len_bytes], "little", signed=False)
            pos += len_bytes

            if off_bytes:
                offset_raw = int.from_bytes(data[pos:pos+off_bytes], "little", signed=True)
                lcn += offset_raw
                abs_offset = lcn * self.cluster_size
            else:
                abs_offset = 0  # sparse run

            pos   += off_bytes
            length = length_raw * self.cluster_size
            runs.append((abs_offset, length))

        return runs

# ════════════════════════════════════════════════════════════════════
# PARSEUR ext2/3/4
# ════════════════════════════════════════════════════════════════════

class Ext4Parser:
    INODE_SIZE_DEFAULT = 128
    EXT4_FEATURE_EXTENTS = 0x40

    def __init__(self, reader, fs_type: FSType):
        self.reader  = reader
        self.fs_type = fs_type
        self._parse_superblock()

    def _parse_superblock(self):
        sb = self.reader.read_at(1024, 1024)
        self.inodes_count      = struct.unpack_from("<I", sb, 0)[0]
        self.blocks_count      = struct.unpack_from("<I", sb, 4)[0]
        self.block_size        = 1024 << struct.unpack_from("<I", sb, 24)[0]
        self.blocks_per_group  = struct.unpack_from("<I", sb, 32)[0]
        self.inodes_per_group  = struct.unpack_from("<I", sb, 40)[0]
        self.inode_size        = struct.unpack_from("<H", sb, 88)[0] or self.INODE_SIZE_DEFAULT
        self.feature_incompat  = struct.unpack_from("<I", sb, 96)[0]
        self.desc_size         = struct.unpack_from("<H", sb, 254)[0] if len(sb) >= 256 else 32
        self.desc_size         = max(self.desc_size, 32)

    def _group_desc_offset(self, group: int) -> int:
        """Offset du descripteur de groupe."""
        gdt_block = 1 if self.block_size == 1024 else 0
        return (gdt_block + 1) * self.block_size + group * self.desc_size

    def _inode_offset(self, inode_num: int) -> int:
        """Offset d'un inode dans l'image."""
        group      = (inode_num - 1) // self.inodes_per_group
        local_idx  = (inode_num - 1) % self.inodes_per_group
        gd         = self.reader.read_at(self._group_desc_offset(group), self.desc_size)
        inode_table_lo = struct.unpack_from("<I", gd, 8)[0]
        inode_table_hi = struct.unpack_from("<I", gd, 40)[0] if self.desc_size >= 44 else 0
        inode_table    = inode_table_lo | (inode_table_hi << 32)
        return inode_table * self.block_size + local_idx * self.inode_size

    def parse_deleted(self) -> list[DeletedEntry]:
        """
        Scan les blocs de répertoire pour trouver les entrées supprimées.
        Une entrée ext est supprimée si son inode = 0 mais qu'elle a encore
        un nom, ou si le mode de l'inode est 0 mais que la taille > 0.
        """
        entries = []
        # Parcourir les blocs de répertoire du groupe 0 (root)
        self._scan_dir_blocks(2, "/", entries, depth=0)  # inode 2 = root
        return entries

    def _scan_dir_blocks(self, inode_num: int, path: str,
                          entries: list, depth: int):
        if depth > 8 or inode_num < 2:
            return
        try:
            inode_off = self._inode_offset(inode_num)
            raw_inode = self.reader.read_at(inode_off, self.inode_size)
            if not raw_inode: return

            mode  = struct.unpack_from("<H", raw_inode, 0)[0]
            size  = struct.unpack_from("<I", raw_inode, 4)[0]
            atime = datetime.datetime.fromtimestamp(struct.unpack_from("<I", raw_inode, 8)[0]) if struct.unpack_from("<I", raw_inode, 8)[0] else None
            ctime = datetime.datetime.fromtimestamp(struct.unpack_from("<I", raw_inode, 12)[0]) if struct.unpack_from("<I", raw_inode, 12)[0] else None
            mtime = datetime.datetime.fromtimestamp(struct.unpack_from("<I", raw_inode, 16)[0]) if struct.unpack_from("<I", raw_inode, 16)[0] else None

            blocks = self._get_blocks(raw_inode)
            for block in blocks[:32]:
                try:
                    data = self.reader.read_at(block * self.block_size, self.block_size)
                    self._parse_dir_block(data, path, entries, depth)
                except:
                    pass
        except:
            pass

    def _get_blocks(self, raw_inode: bytes) -> list[int]:
        """Retourne les numéros de blocs d'un inode (direct seulement pour simplifier)."""
        blocks = []
        for i in range(12):  # 12 blocs directs
            b = struct.unpack_from("<I", raw_inode, 40 + i*4)[0]
            if b: blocks.append(b)
        return blocks

    def _parse_dir_block(self, data: bytes, path: str,
                          entries: list, depth: int):
        pos = 0
        while pos + 8 < len(data):
            inode_num = struct.unpack_from("<I", data, pos)[0]
            rec_len   = struct.unpack_from("<H", data, pos+4)[0]
            name_len  = data[pos+6]
            file_type = data[pos+7]

            if rec_len < 8 or pos + rec_len > len(data):
                break

            name = data[pos+8:pos+8+name_len].decode("utf-8","replace")

            if inode_num == 0 and name and name not in (".", ".."):
                # Entrée supprimée
                entries.append(DeletedEntry(
                    name          = name,
                    size          = 0,
                    fs_type       = self.fs_type,
                    first_cluster = 0,
                    runs          = [],
                    path          = path + name,
                    is_dir        = file_type == 2,
                ))
            elif inode_num > 1 and name not in (".", "..") and file_type == 2 and depth < 8:
                self._scan_dir_blocks(inode_num, path + name + "/", entries, depth+1)

            pos += rec_len

# ════════════════════════════════════════════════════════════════════
# API PUBLIQUE
# ════════════════════════════════════════════════════════════════════

def parse_filesystem(reader) -> tuple[FSType, list[DeletedEntry]]:
    """
    Point d'entrée principal.
    Détecte le FS et retourne (type, liste des entrées supprimées).
    """
    fs_type = detect_fs(reader)
    entries = []

    try:
        if fs_type in (FSType.FAT12, FSType.FAT16, FSType.FAT32):
            parser  = FAT32Parser(reader, fs_type)
            entries = parser.parse_deleted()

        elif fs_type == FSType.NTFS:
            parser  = NTFSParser(reader)
            entries = parser.parse_deleted()

        elif fs_type in (FSType.EXT2, FSType.EXT3, FSType.EXT4):
            parser  = Ext4Parser(reader, fs_type)
            entries = parser.parse_deleted()

        elif fs_type == FSType.EXFAT:
            parser  = ExFATParser(reader)
            entries = parser.parse_deleted()

        elif fs_type == FSType.HFS_PLUS:
            parser  = HFSPlusParser(reader)
            entries = parser.parse_deleted()

        elif fs_type == FSType.APFS:
            parser  = APFSParser(reader)
            entries = parser.parse_deleted()

        elif fs_type == FSType.F2FS:
            parser  = F2FSParser(reader)
            entries = parser.parse_deleted()

        elif fs_type == FSType.YAFFS2:
            parser  = YAFFS2Parser(reader)
            entries = parser.parse_deleted()

        elif fs_type == FSType.BTRFS:
            parser  = BtrfsParser(reader)
            entries = parser.parse_deleted()
    except Exception as e:
        print(f"  [!] Erreur parseur FS : {e}")

    return fs_type, entries

def reconstruct_file(reader, entry: DeletedEntry, output_path: Path) -> bool:
    """
    Reconstruit un fichier supprimé depuis ses runs.
    Retourne True si succès.
    """
    if not entry.runs:
        return False
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "wb") as out:
            remaining = entry.size if entry.size > 0 else float("inf")
            for (offset, length) in entry.runs:
                to_read = min(length, remaining) if remaining != float("inf") else length
                if to_read <= 0:
                    break
                data = reader.read_at(offset, int(to_read))
                if not data:
                    break
                out.write(data)
                if remaining != float("inf"):
                    remaining -= len(data)
        return True
    except Exception:
        return False


# ════════════════════════════════════════════════════════════════════
# PARSEUR exFAT
# ════════════════════════════════════════════════════════════════════

class ExFATParser:
    """
    exFAT — format Microsoft pour cartes SD et clés USB > 32 Go.
    Structure : Boot region + FAT + Cluster Heap + Root directory
    """
    def __init__(self, reader):
        self.reader = reader
        self._parse_boot()

    def _parse_boot(self):
        boot = self.reader.read_at(0, 512)
        # Offsets exFAT (différents du FAT32)
        self.bytes_per_sector_shift  = boot[108]
        self.sects_per_cluster_shift = boot[109]
        self.bytes_per_sector        = 1 << self.bytes_per_sector_shift
        self.cluster_size            = self.bytes_per_sector * (1 << self.sects_per_cluster_shift)
        self.fat_offset              = struct.unpack_from("<I", boot, 80)[0] * self.bytes_per_sector
        self.cluster_heap_offset     = struct.unpack_from("<I", boot, 84)[0] * self.bytes_per_sector
        self.first_cluster_of_root   = struct.unpack_from("<I", boot, 96)[0]

    def _cluster_to_offset(self, cluster: int) -> int:
        return self.cluster_heap_offset + (cluster - 2) * self.cluster_size

    def parse_deleted(self) -> list[DeletedEntry]:
        entries = []
        self._scan_directory(self.first_cluster_of_root, "/", entries, depth=0)
        return entries

    def _scan_directory(self, first_cluster: int, path: str,
                        entries: list, depth: int):
        if depth > 12: return
        offset = self._cluster_to_offset(first_cluster)
        pos    = offset

        while pos < offset + self.cluster_size * 8:
            try:
                raw = self.reader.read_at(pos, 32)
            except: break
            if not raw or len(raw) < 32: break

            entry_type = raw[0]
            if entry_type == 0x00: break

            # Type 0x85 = File Entry (0x05 = supprimé)
            if entry_type in (0x85, 0x05):
                in_use = (entry_type == 0x85)
                if not in_use:
                    # Lire le Stream Extension (entrée suivante)
                    try:
                        stream = self.reader.read_at(pos + 32, 32)
                        fname_entry = self.reader.read_at(pos + 64, 32)
                        if stream[0] in (0xC0, 0x40):  # Stream Extension
                            size = struct.unpack_from("<Q", stream, 8)[0]
                            first_cluster = struct.unpack_from("<I", stream, 20)[0]
                            # File Name Entry
                            if fname_entry[0] in (0xC1, 0x41):
                                name_len = stream[3]
                                name = fname_entry[2:2+min(name_len*2,30)].decode("utf-16-le","replace")
                                entries.append(DeletedEntry(
                                    name=name, size=size,
                                    fs_type=FSType.EXFAT,
                                    first_cluster=first_cluster,
                                    runs=[(self._cluster_to_offset(first_cluster), size)]
                                          if first_cluster >= 2 else [],
                                    path=path+name,
                                ))
                    except: pass
            pos += 32

# ════════════════════════════════════════════════════════════════════
# PARSEUR HFS+ (macOS)
# ════════════════════════════════════════════════════════════════════

class HFSPlusParser:
    """
    HFS+ — système de fichiers macOS jusqu'à High Sierra.
    Basé sur des B-trees : Catalog B-tree pour les fichiers,
    Extents B-tree pour les runs de données.
    """
    SECTOR_SIZE     = 512
    HFS_PLUS_MAGIC  = 0x482B  # 'H+'
    HFSX_MAGIC      = 0x4858  # 'HX'

    def __init__(self, reader):
        self.reader = reader
        self._parse_volume_header()

    def _parse_volume_header(self):
        # Volume Header à offset 1024 (secteur 2)
        vh = self.reader.read_at(1024, 512)
        magic = struct.unpack_from(">H", vh, 0)[0]
        if magic not in (self.HFS_PLUS_MAGIC, self.HFSX_MAGIC):
            raise ValueError(f"Magic HFS+ invalide : 0x{magic:04x}")

        self.block_size        = struct.unpack_from(">I", vh, 40)[0]
        self.total_blocks      = struct.unpack_from(">I", vh, 44)[0]
        self.free_blocks       = struct.unpack_from(">I", vh, 48)[0]

        # Catalog file fork descriptor (offset 336 dans VH)
        self.catalog_size      = struct.unpack_from(">Q", vh, 336)[0]
        # Premier extent du catalog (clrStBk = start block)
        self.catalog_start_blk = struct.unpack_from(">I", vh, 360)[0]

    def _block_to_offset(self, block: int) -> int:
        return block * self.block_size

    def parse_deleted(self) -> list[DeletedEntry]:
        """
        Scan les nœuds du Catalog B-tree pour les enregistrements supprimés.
        Dans HFS+, les entrées supprimées restent dans le B-tree avec
        un type de nœud différent jusqu'au journal replay.
        """
        entries = []
        try:
            catalog_offset = self._block_to_offset(self.catalog_start_blk)
            # Lire le nœud header du B-tree
            node_hdr = self.reader.read_at(catalog_offset, 512)
            if len(node_hdr) < 14: return entries

            node_size  = struct.unpack_from(">H", node_hdr, 32)[0] or 4096
            total_nodes= struct.unpack_from(">I", node_hdr, 20)[0]

            # Scanner les nœuds feuilles (type 0xFF = leaf node)
            for node_idx in range(min(total_nodes, 50000)):
                node_off = catalog_offset + node_idx * node_size
                try:
                    node = self.reader.read_at(node_off, node_size)
                    if not node or len(node) < 14: continue

                    node_type = node[8]
                    if node_type != 0xFF: continue  # leaf node uniquement

                    num_records = struct.unpack_from(">H", node, 10)[0]
                    # Lire les offsets de records depuis la fin du nœud
                    for r in range(min(num_records, 128)):
                        rec_off_idx = node_size - (r+1)*2
                        if rec_off_idx < 14: break
                        rec_off = struct.unpack_from(">H", node, rec_off_idx)[0]
                        if rec_off < 14 or rec_off >= node_size: continue

                        # Key length
                        key_len = struct.unpack_from(">H", node, rec_off)[0]
                        if key_len == 0 or rec_off + key_len >= node_size: continue

                        # Data offset
                        data_off = rec_off + 2 + key_len
                        if data_off + 2 >= node_size: continue

                        record_type = struct.unpack_from(">H", node, data_off)[0]

                        # Type 1 = folder, 2 = file, -1/-2 = thread
                        # On cherche les fichiers (type 2)
                        if record_type == 2:
                            try:
                                # Flags (offset +2 depuis data)
                                flags = struct.unpack_from(">H", node, data_off+2)[0]
                                # Bit 0x0080 = has been deleted in some implementations
                                # Taille des données fork
                                data_fork_size = struct.unpack_from(">Q", node, data_off+88)[0]
                                # Nom depuis la clé
                                name_len = struct.unpack_from(">H", node, rec_off+6)[0]
                                name = node[rec_off+8:rec_off+8+name_len*2].decode("utf-16-be","replace")

                                # Timestamps HFS+ (secondes depuis 1904-01-01)
                                HFS_EPOCH = datetime.datetime(1904,1,1)
                                ctime_raw = struct.unpack_from(">I", node, data_off+12)[0]
                                mtime_raw = struct.unpack_from(">I", node, data_off+16)[0]
                                try:
                                    ctime = HFS_EPOCH + datetime.timedelta(seconds=ctime_raw)
                                    mtime = HFS_EPOCH + datetime.timedelta(seconds=mtime_raw)
                                except: ctime = mtime = None

                                # Premier extent du data fork
                                ext_start = struct.unpack_from(">I", node, data_off+100)[0]
                                ext_count = struct.unpack_from(">I", node, data_off+104)[0]
                                runs = [(self._block_to_offset(ext_start),
                                         ext_count * self.block_size)] if ext_start else []

                                if name and data_fork_size > 0:
                                    entries.append(DeletedEntry(
                                        name=name, size=data_fork_size,
                                        fs_type=FSType.HFS_PLUS,
                                        first_cluster=ext_start,
                                        runs=runs, ctime=ctime, mtime=mtime,
                                        path=name,
                                    ))
                            except: pass
                except: pass
        except Exception as e:
            pass
        return entries

# ════════════════════════════════════════════════════════════════════
# PARSEUR APFS (macOS Sierra+)
# ════════════════════════════════════════════════════════════════════

class APFSParser:
    """
    APFS — Apple File System (macOS 10.13+, iOS 10.3+).
    Spec non officielle — basé sur reverse engineering (libapfs, apfs-fuse).

    Structure :
      Container Superblock (nx_superblock_t) → Object Map B-tree
      → Volume Superblock (apfs_superblock_t) → File System Tree B-tree
      → Inode records + Extent records

    Stratégie ici : wrapper apfs-fuse si disponible,
    sinon parseur natif partiel (container + volume headers).
    """
    NXSB_MAGIC = 0x4253584E  # 'NXSB'
    APSB_MAGIC = 0x42535041  # 'APSB'
    BLOCK_SIZE  = 4096

    def __init__(self, reader):
        self.reader     = reader
        self.block_size = self.BLOCK_SIZE
        self._parse_container()

    def _parse_container(self):
        """Parse le Container Superblock (bloc 0)."""
        blk = self.reader.read_at(0, 4096)
        magic = struct.unpack_from("<I", blk, 32)[0]
        if magic != self.NXSB_MAGIC:
            raise ValueError(f"Magic APFS invalide : 0x{magic:08x}")

        self.block_size     = struct.unpack_from("<I", blk, 36)[0] or 4096
        self.block_count    = struct.unpack_from("<Q", blk, 40)[0]
        # Object Map BTree root (omap_oid)
        self.omap_oid       = struct.unpack_from("<Q", blk, 160)[0]
        # Volume oids array (nx_fs_oid)
        self.volume_oids    = []
        for i in range(100):
            oid = struct.unpack_from("<Q", blk, 184 + i*8)[0]
            if oid == 0: break
            self.volume_oids.append(oid)

    def _read_block(self, oid: int) -> bytes:
        return self.reader.read_at(oid * self.block_size, self.block_size)

    def parse_deleted(self) -> list[DeletedEntry]:
        """
        Tente d'abord via apfs-fuse monté, sinon parseur natif.
        """
        # Méthode 1 : apfs-fuse (outil externe open source)
        entries = self._try_apfs_fuse()
        if entries is not None:
            return entries

        # Méthode 2 : parseur natif partiel
        return self._parse_native()

    def _try_apfs_fuse(self) -> list[DeletedEntry] | None:
        """
        Si apfs-fuse est installé, monter le volume et lister les fichiers.
        apfs-fuse expose les fichiers supprimés via l'option --recover.
        """
        if not shutil.which("apfs-fuse"):
            return None

        import tempfile, subprocess
        mnt = tempfile.mkdtemp(prefix="apfs_mnt_")
        try:
            r = subprocess.run(
                ["apfs-fuse", "-o", "recover", self.reader.path, mnt],
                capture_output=True, timeout=60
            )
            if r.returncode != 0:
                return None

            entries = []
            for root, dirs, files in os.walk(mnt):
                for fname in files:
                    fp  = Path(root) / fname
                    rel = str(fp.relative_to(mnt))
                    try:
                        st  = fp.stat()
                        entries.append(DeletedEntry(
                            name=fname, size=st.st_size,
                            fs_type=FSType.APFS,
                            first_cluster=0,
                            runs=[(0, st.st_size)],
                            mtime=datetime.datetime.fromtimestamp(st.st_mtime),
                            path=rel,
                        ))
                    except: pass

            subprocess.run(["fusermount","-u",mnt], capture_output=True)
            return entries
        except Exception:
            try: subprocess.run(["fusermount","-u",mnt], capture_output=True)
            except: pass
            return None
        finally:
            try: os.rmdir(mnt)
            except: pass

    def _parse_native(self) -> list[DeletedEntry]:
        """
        Parseur APFS natif partiel — scan les blocs du File System Tree
        et extrait les inodes avec taille > 0.
        """
        entries = []
        try:
            for vol_oid in self.volume_oids[:8]:
                try:
                    vol_blk = self._read_block(vol_oid)
                    magic   = struct.unpack_from("<I", vol_blk, 32)[0]
                    if magic != self.APSB_MAGIC: continue

                    # Root tree oid (apfs_root_tree_oid at offset 144)
                    root_oid = struct.unpack_from("<Q", vol_blk, 144)[0]
                    if root_oid == 0: continue

                    # Scan des blocs autour du root tree
                    self._scan_fstree(root_oid, entries)
                except: continue
        except: pass
        return entries

    def _scan_fstree(self, root_oid: int, entries: list):
        """Scan récursif du B-tree APFS."""
        visited = set()
        queue   = [root_oid]

        while queue and len(entries) < 100000:
            oid = queue.pop(0)
            if oid in visited or oid == 0: continue
            visited.add(oid)

            try:
                blk  = self._read_block(oid)
                # Node header : type à offset 40
                node_type = struct.unpack_from("<H", blk, 40)[0] & 0xF
                # 1=root, 2=internal, 3=leaf, 4=invalid

                if node_type in (1, 2):
                    # Nœud interne : extraire les OIDs enfants
                    nkeys = struct.unpack_from("<H", blk, 48)[0]
                    toc_off = struct.unpack_from("<H", blk, 56)[0] + 56
                    for i in range(min(nkeys, 256)):
                        try:
                            child_oid = struct.unpack_from("<Q", blk, toc_off + i*16 + 8)[0]
                            if child_oid and child_oid not in visited:
                                queue.append(child_oid)
                        except: pass

                elif node_type == 3:
                    # Nœud feuille : extraire les records
                    nkeys = struct.unpack_from("<H", blk, 48)[0]
                    toc_off = struct.unpack_from("<H", blk, 56)[0] + 56

                    for i in range(min(nkeys, 256)):
                        try:
                            key_off = struct.unpack_from("<H", blk, toc_off + i*4)[0]
                            val_off = struct.unpack_from("<H", blk, toc_off + i*4 + 2)[0]

                            # APFS key : obj_id_and_type (8 bytes)
                            key_data = blk[56 + key_off:56 + key_off + 8]
                            if len(key_data) < 8: continue

                            obj_type = (struct.unpack_from("<Q", key_data)[0] >> 60) & 0xF
                            obj_id   = struct.unpack_from("<Q", key_data)[0] & 0x0FFFFFFFFFFFFFFF

                            # Type 3 = APFS_TYPE_INODE
                            if obj_type == 3:
                                # Inode value
                                val_abs = self.block_size - 40 - val_off
                                if val_abs < 0 or val_abs + 96 > self.block_size: continue
                                val_data = blk[val_abs:val_abs + 96]
                                if len(val_data) < 96: continue

                                size       = struct.unpack_from("<Q", val_data, 32)[0]
                                mtime_ns   = struct.unpack_from("<Q", val_data, 16)[0]
                                ctime_ns   = struct.unpack_from("<Q", val_data, 24)[0]
                                parent_id  = struct.unpack_from("<Q", val_data, 8)[0]

                                try:
                                    mtime = datetime.datetime.fromtimestamp(mtime_ns/1e9)
                                    ctime = datetime.datetime.fromtimestamp(ctime_ns/1e9)
                                except:
                                    mtime = ctime = None

                                if size > 0:
                                    entries.append(DeletedEntry(
                                        name=f"inode_{obj_id}",
                                        size=size,
                                        fs_type=FSType.APFS,
                                        first_cluster=obj_id,
                                        runs=[],
                                        mtime=mtime, ctime=ctime,
                                        path=f"inode_{obj_id}",
                                    ))
                        except: pass
            except: pass

# ════════════════════════════════════════════════════════════════════
# PARSEUR F2FS (Android moderne)
# ════════════════════════════════════════════════════════════════════

class F2FSParser:
    """
    F2FS — Flash-Friendly File System, utilisé sur Android (eMMC/UFS).
    Superblock à offset 1024, Node Address Table (NAT), Segment Info Table.
    """
    F2FS_MAGIC = 0xF2F52010

    def __init__(self, reader):
        self.reader = reader
        self._parse_superblock()

    def _parse_superblock(self):
        sb = self.reader.read_at(1024, 3072)
        magic = struct.unpack_from("<I", sb, 0)[0]
        if magic != self.F2FS_MAGIC:
            raise ValueError(f"Magic F2FS invalide : 0x{magic:08x}")

        self.log_blocksize    = struct.unpack_from("<I", sb, 8)[0]
        self.block_size       = 1 << self.log_blocksize  # typiquement 4096
        self.log_blocks_per_seg = struct.unpack_from("<I", sb, 12)[0]
        self.segs_per_sec     = struct.unpack_from("<I", sb, 16)[0]
        self.secs_per_zone    = struct.unpack_from("<I", sb, 20)[0]
        self.segment_count    = struct.unpack_from("<I", sb, 24)[0]
        self.segment0_blkaddr = struct.unpack_from("<I", sb, 52)[0]
        self.nat_blkaddr      = struct.unpack_from("<I", sb, 60)[0]
        self.root_ino         = struct.unpack_from("<I", sb, 116)[0]

        # Volume name (UTF-16LE, 512 bytes max)
        try:
            self.volume_name = sb[136:648].decode("utf-16-le","replace").rstrip("\x00")
        except:
            self.volume_name = ""

    def _blk_to_offset(self, blkaddr: int) -> int:
        return (blkaddr - self.segment0_blkaddr) * self.block_size + \
               self.segment0_blkaddr * self.block_size

    def _nat_entry_offset(self, nid: int) -> int:
        """Retourne l'offset de l'entrée NAT pour un NID donné."""
        # Chaque bloc NAT contient 455 entrées (block_size / sizeof(nat_entry))
        entries_per_block = self.block_size // 8
        block_off = nid // entries_per_block
        entry_off = nid % entries_per_block
        nat_abs   = self.nat_blkaddr * self.block_size + block_off * self.block_size
        return nat_abs + entry_off * 8

    def _read_inode(self, nid: int) -> bytes | None:
        """Lit un inode F2FS depuis la NAT."""
        try:
            nat_off = self._nat_entry_offset(nid)
            nat_entry = self.reader.read_at(nat_off, 8)
            blkaddr = struct.unpack_from("<I", nat_entry, 4)[0]
            if blkaddr == 0 or blkaddr == 0xFFFFFFFF:
                return None
            inode_off = blkaddr * self.block_size
            return self.reader.read_at(inode_off, self.block_size)
        except:
            return None

    def parse_deleted(self) -> list[DeletedEntry]:
        """
        Scan la NAT pour trouver les inodes avec i_nlink=0 (supprimés)
        mais dont le bloc est encore alloué.
        """
        entries = []
        # Scanner les NIDs de 3 (root=3 dans F2FS) jusqu'à une limite raisonnable
        max_nid = min(self.segment_count * 512, 1_000_000)

        for nid in range(3, max_nid):
            try:
                inode = self._read_inode(nid)
                if not inode or len(inode) < 200: continue

                # F2FS inode structure
                i_mode   = struct.unpack_from("<H", inode, 0)[0]
                i_nlink  = struct.unpack_from("<I", inode, 8)[0]
                i_size   = struct.unpack_from("<Q", inode, 16)[0]
                i_ctime  = struct.unpack_from("<I", inode, 32)[0]
                i_mtime  = struct.unpack_from("<I", inode, 40)[0]
                i_namelen= struct.unpack_from("<I", inode, 108)[0]

                # Inode supprimé = nlink==0 mais taille > 0
                if i_nlink == 0 and i_size > 0 and i_size < 10*1024*1024*1024:
                    is_dir = bool(i_mode & 0x4000)
                    is_file= bool(i_mode & 0x8000)
                    if not (is_dir or is_file): continue

                    # Nom de fichier (stocké dans l'inode F2FS)
                    name = ""
                    if 0 < i_namelen <= 255:
                        try:
                            name = inode[116:116+i_namelen].decode("utf-8","replace")
                        except: pass
                    if not name:
                        name = f"f2fs_inode_{nid}"

                    try:
                        mtime = datetime.datetime.fromtimestamp(i_mtime)
                        ctime = datetime.datetime.fromtimestamp(i_ctime)
                    except:
                        mtime = ctime = None

                    # Blocs directs (direct_blks dans f2fs_inode, offset 152)
                    runs = []
                    for di in range(min(12, (self.block_size - 152) // 4)):
                        blkaddr = struct.unpack_from("<I", inode, 152 + di*4)[0]
                        if blkaddr and blkaddr != 0xFFFFFFFF:
                            runs.append((blkaddr * self.block_size, self.block_size))

                    entries.append(DeletedEntry(
                        name=name, size=i_size,
                        fs_type=FSType.F2FS,
                        first_cluster=nid,
                        runs=runs,
                        mtime=mtime, ctime=ctime,
                        is_dir=is_dir,
                        path=name,
                    ))

                    if len(entries) % 1000 == 0:
                        print(f"\r  F2FS : {len(entries)} entrées trouvées (NID {nid})…",
                              end="", flush=True)
            except: continue

        if entries:
            print(f"\r  F2FS : {len(entries)} entrées trouvées              ")
        return entries

# ════════════════════════════════════════════════════════════════════
# PARSEUR YAFFS2 (Android ancien — NAND flash)
# ════════════════════════════════════════════════════════════════════

class YAFFS2Parser:
    """
    YAFFS2 — Yet Another Flash File System 2.
    Utilisé sur les anciens Android (2.x, 3.x) sur mémoire NAND.
    Structure : chunks de 2048 bytes + 64 bytes d'OOB (spare area)
    Chaque chunk contient soit un objet header soit des données.
    """
    YAFFS_OBJECT_TYPE_FILE      = 1
    YAFFS_OBJECT_TYPE_DIRECTORY = 2
    YAFFS_OBJECT_TYPE_SYMLINK   = 3
    YAFFS_MAGIC                 = 0x5941FF53  # dans l'OOB

    # Tailles de chunk courantes
    CHUNK_SIZES = [
        (2048, 64),   # NAND classique
        (4096, 128),  # NAND haute densité
        (512,  16),   # ancien NAND
    ]

    def __init__(self, reader):
        self.reader     = reader
        self.chunk_size, self.oob_size = self._detect_geometry()
        self.total_size = self.chunk_size + self.oob_size

    def _detect_geometry(self) -> tuple[int, int]:
        """Détecte la géométrie NAND en cherchant les magic bytes."""
        for cs, oos in self.CHUNK_SIZES:
            total = cs + oos
            try:
                # Lire l'OOB du premier chunk
                oob = self.reader.read_at(cs, oos)
                if len(oob) >= 8:
                    # Magic YAFFS dans l'OOB : seq_number > 0, object_id > 0
                    seq_num = struct.unpack_from("<I", oob, 4)[0]
                    obj_id  = struct.unpack_from("<I", oob, 0)[0]
                    if 0 < seq_num < 0xFFFFFFFF and 0 < obj_id < 0xFFFE:
                        return cs, oos
            except: continue
        return 2048, 64  # défaut

    def _read_chunk(self, chunk_idx: int) -> tuple[bytes, bytes]:
        """Retourne (data, oob) pour un chunk donné."""
        off  = chunk_idx * self.total_size
        data = self.reader.read_at(off, self.chunk_size)
        oob  = self.reader.read_at(off + self.chunk_size, self.oob_size)
        return data, oob

    def parse_deleted(self) -> list[DeletedEntry]:
        """
        Scan tous les chunks YAFFS2.
        Un objet est "supprimé" si son header a un chunk_id=0
        mais que seq_number est < le dernier seq_number connu pour cet object_id.
        """
        objects   = {}  # object_id → {seq: ..., type: ..., name: ..., size: ...}
        deleted   = []
        source_size = self.reader.size
        max_chunks  = source_size // self.total_size

        for ci in range(min(max_chunks, 2_000_000)):
            try:
                data, oob = self._read_chunk(ci)
                if not oob or len(oob) < 8: continue

                obj_id   = struct.unpack_from("<I", oob, 0)[0]
                chunk_id = struct.unpack_from("<I", oob, 4)[0] & 0x000FFFFF
                seq_num  = struct.unpack_from("<I", oob, 8)[0] if len(oob) >= 12 else 0

                if obj_id == 0 or obj_id >= 0xFFFE: continue
                if seq_num == 0 or seq_num == 0xFFFFFFFF: continue

                # chunk_id == 0 → objet header
                if chunk_id == 0 and len(data) >= 256:
                    obj_type = struct.unpack_from("<I", data, 0)[0]
                    parent_obj = struct.unpack_from("<I", data, 4)[0]
                    name_raw = data[10:266]
                    name = name_raw.split(b"\x00")[0].decode("utf-8","replace")
                    size = struct.unpack_from("<I", data, 268)[0] if len(data) >= 272 else 0

                    obj_info = {
                        "seq": seq_num, "type": obj_type,
                        "name": name, "size": size,
                        "parent": parent_obj, "chunk": ci,
                    }

                    if obj_id in objects:
                        # Version plus ancienne → supprimée
                        if seq_num < objects[obj_id]["seq"]:
                            deleted.append(obj_info)
                        else:
                            deleted.append(objects[obj_id])
                            objects[obj_id] = obj_info
                    else:
                        objects[obj_id] = obj_info

                if ci % 10000 == 0 and ci > 0:
                    print(f"\r  YAFFS2 : chunk {ci}/{max_chunks} "
                          f"— {len(deleted)} supprimés trouvés…",
                          end="", flush=True)
            except: continue

        if deleted:
            print(f"\r  YAFFS2 : {len(deleted)} objets supprimés              ")

        entries = []
        for obj in deleted:
            if obj["type"] not in (self.YAFFS_OBJECT_TYPE_FILE,
                                    self.YAFFS_OBJECT_TYPE_DIRECTORY):
                continue
            if not obj["name"]: continue

            # Retrouver les chunks de données pour reconstruire le fichier
            runs = []
            chunk_idx = obj["chunk"]
            # Les données suivent l'header dans les chunks suivants
            expected_size = obj["size"]
            if expected_size > 0:
                runs = [(chunk_idx * self.total_size, expected_size)]

            entries.append(DeletedEntry(
                name=obj["name"], size=obj["size"],
                fs_type=FSType.YAFFS2,
                first_cluster=obj["chunk"],
                runs=runs,
                path=obj["name"],
                is_dir=(obj["type"] == self.YAFFS_OBJECT_TYPE_DIRECTORY),
            ))

        return entries

# ════════════════════════════════════════════════════════════════════
# PARSEUR Btrfs
# ════════════════════════════════════════════════════════════════════

class BtrfsParser:
    """
    Btrfs — B-tree file system Linux.
    Superblock à 65536 (0x10000), copies miroirs à 256Mo et 1Go.
    Structure : Tree of Trees → FS Tree → Inode items.
    Les fichiers supprimés restent dans le log tree jusqu'au checkpoint.
    """
    BTRFS_MAGIC     = 0x4D5F53665248425F  # '_BHRfS_M'
    SUPERBLOCK_OFF  = 65536

    def __init__(self, reader):
        self.reader = reader
        self._parse_superblock()

    def _parse_superblock(self):
        sb = self.reader.read_at(self.SUPERBLOCK_OFF, 4096)
        magic = struct.unpack_from("<Q", sb, 64)[0]
        if magic != self.BTRFS_MAGIC:
            raise ValueError(f"Magic Btrfs invalide : 0x{magic:016x}")

        self.node_size        = struct.unpack_from("<I", sb, 60)[0] or 16384
        self.sector_size      = struct.unpack_from("<I", sb, 48)[0] or 4096
        self.root_tree_root   = struct.unpack_from("<Q", sb, 144)[0]
        self.chunk_tree_root  = struct.unpack_from("<Q", sb, 160)[0]
        self.log_tree_root    = struct.unpack_from("<Q", sb, 176)[0]
        self.fs_tree_objectid = 5  # BTRFS_FS_TREE_OBJECTID

    def _logical_to_physical(self, logical: int) -> int:
        """
        Conversion adresse logique → physique via le chunk tree.
        Simplification : offset direct pour les images sans striping.
        """
        return logical  # pour les images raw simples

    def _read_node(self, logical_addr: int) -> bytes:
        phys = self._logical_to_physical(logical_addr)
        return self.reader.read_at(phys, self.node_size)

    def parse_deleted(self) -> list[DeletedEntry]:
        """
        Cherche les inodes supprimés dans le FS tree et le log tree.
        Un inode Btrfs supprimé a encore ses items dans le tree
        jusqu'au prochain commit si le log tree n'est pas rejoué.
        """
        entries = []
        # Scanner le log tree si présent (contient les changements non encore committed)
        if self.log_tree_root:
            try:
                self._scan_tree(self.log_tree_root, entries, "log")
            except: pass
        # Scanner les FS trees
        try:
            self._scan_root_tree(entries)
        except: pass
        return entries

    def _scan_root_tree(self, entries: list):
        """Trouve les FS trees depuis le root tree."""
        try:
            node = self._read_node(self.root_tree_root)
            if not node: return
            self._scan_tree(self.root_tree_root, entries, "root")
        except: pass

    def _scan_tree(self, root_addr: int, entries: list, tree_name: str):
        """Parcours DFS du B-tree Btrfs."""
        visited = set()
        stack   = [root_addr]

        while stack:
            addr = stack.pop()
            if addr in visited or addr == 0: continue
            visited.add(addr)

            try:
                node = self._read_node(addr)
                if not node or len(node) < 101: continue

                # Header Btrfs node
                nritems = struct.unpack_from("<I", node, 96)[0]
                level   = node[100]

                if level > 0:
                    # Nœud interne : pointer items
                    for i in range(min(nritems, 512)):
                        off = 101 + i * 33
                        if off + 33 > len(node): break
                        child_addr = struct.unpack_from("<Q", node, off + 17)[0]
                        if child_addr and child_addr not in visited:
                            stack.append(child_addr)
                else:
                    # Nœud feuille : key + item data
                    for i in range(min(nritems, 256)):
                        key_off = 101 + i * 25
                        if key_off + 25 > len(node): break

                        obj_id   = struct.unpack_from("<Q", node, key_off)[0]
                        item_type= node[key_off + 8]
                        data_off = struct.unpack_from("<I", node, key_off + 17)[0]
                        data_size= struct.unpack_from("<I", node, key_off + 21)[0]

                        # Type 1 = BTRFS_INODE_ITEM_KEY
                        if item_type == 1 and data_size >= 160:
                            abs_data = 101 + nritems * 25 + data_off
                            if abs_data + 160 > len(node): continue

                            inode_data = node[abs_data:abs_data+160]
                            nlink  = struct.unpack_from("<I", inode_data, 36)[0]
                            size   = struct.unpack_from("<Q", inode_data, 16)[0]
                            mode   = struct.unpack_from("<I", inode_data, 44)[0]
                            mtime_s= struct.unpack_from("<Q", inode_data, 88)[0]
                            ctime_s= struct.unpack_from("<Q", inode_data, 72)[0]

                            # Supprimé = nlink==0, taille > 0
                            if nlink == 0 and 0 < size < 100*1024*1024*1024:
                                is_dir = bool(mode & 0x4000)
                                try:
                                    mtime = datetime.datetime.fromtimestamp(mtime_s)
                                    ctime = datetime.datetime.fromtimestamp(ctime_s)
                                except:
                                    mtime = ctime = None

                                entries.append(DeletedEntry(
                                    name=f"btrfs_ino_{obj_id}",
                                    size=size,
                                    fs_type=FSType.BTRFS,
                                    first_cluster=obj_id,
                                    runs=[],
                                    mtime=mtime, ctime=ctime,
                                    is_dir=is_dir,
                                    path=f"{tree_name}/ino_{obj_id}",
                                ))
            except: continue

