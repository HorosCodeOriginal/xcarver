# xCarver v4

**Dual-engine forensic file carver — FS-aware recovery + high-performance raw carving**

> Recover deleted files with their original names, directory structure, and timestamps — or carve raw data with 119 byte-signature patterns across 12 file categories. No external dependencies required.

---

## Why xCarver?

Most file carvers do one thing: scan raw bytes for file signatures (Photorec, Foremost, Scalpel). xCarver does two things simultaneously and merges the results:

| Feature | Photorec | Foremost | Scalpel | **xCarver v4** |
|---------|----------|----------|---------|----------------|
| Raw carving | Yes | Yes | Yes | **Yes** |
| FS-aware recovery (original filenames) | No | No | No | **Yes** |
| Entropy analysis (skip encrypted zones) | No | No | No | **Yes** |
| CTF mode + entropy heatmap | No | No | No | **Yes** |
| Session resume | No | No | No | **Yes** |
| SHA256 cross-deduplication FS↔Raw | No | No | No | **Yes** |
| Recursive archive extraction | No | No | No | **Yes** |
| Structural validators (not just magic bytes) | Partial | No | No | **Yes** |
| External JSON signatures | No | Config file | Config file | **Yes** |
| Zero mandatory dependencies | Yes | Yes | Yes | **Yes** |
| Persistent C scanner (single automaton build) | — | — | — | **Yes** |

**The key difference:** when a filesystem (FAT32, NTFS, ext4, HFS+...) is partially intact, xCarver uses its metadata to recover files with their original names, paths, and timestamps — not just `file_00001.jpg`. Raw carving fills in everything else.

---

## Supported filesystems (FS-aware mode)

| Filesystem | Deleted entry recovery | Original names | Timestamps |
|-----------|----------------------|----------------|-----------|
| FAT12 / FAT16 / FAT32 | Yes | Yes | Yes |
| exFAT | Yes | Yes | Yes |
| NTFS | Yes (MFT + $LogFile + $UsnJrnl) | Yes | Yes |
| ext2 / ext3 / ext4 | Yes | Yes | Yes |
| HFS+ | Yes | Yes | Yes |
| APFS | Yes | Yes | Yes |
| F2FS | Yes | Yes | Yes |
| Btrfs | Yes | Yes | Yes |
| YAFFS2 | Yes | Yes | Yes |

---

## Supported file types (119 signatures)

<details>
<summary>Images (22)</summary>

JPEG, PNG, GIF, BMP, TIFF, WebP, PSD, ICO, RAW formats (CR2, CR3, NEF, ARW, DNG), HEIC, AVIF, JXL
</details>

<details>
<summary>Video (12)</summary>

MP4, MOV, MKV, WebM, AVI, 3GP, FLV, WMV, MPEG-1/2, MPEG-TS
</details>

<details>
<summary>Audio (13)</summary>

MP3, OGG, FLAC, WAV, AAC, M4A, WMA, AIFF, APE, Opus, DSD
</details>

<details>
<summary>Documents (18)</summary>

PDF, DOC/DOCX, XLS/XLSX, PPT/PPTX, ODT/ODS/ODP, RTF, LaTeX, MOBI, EPUB, CHM, EML
</details>

<details>
<summary>Archives (13)</summary>

ZIP, RAR4/5, 7Z, GZIP, BZIP2, XZ, ZSTD, LZ4, LZMA, TAR, CAB, ISO, DMG
</details>

<details>
<summary>Databases (8)</summary>

SQLite3, MySQL dump, PostgreSQL dump, MS Access MDB/ACCDB
</details>

<details>
<summary>Executables (9)</summary>

PE (Windows EXE/DLL), ELF (Linux/Unix), Mach-O (macOS), Java .class
</details>

<details>
<summary>Crypto (7)</summary>

PEM certificates, SSH private/public keys, GPG keyrings
</details>

<details>
<summary>Email (4)</summary>

PST, OST, EML (RFC 2822)
</details>

<details>
<summary>Forensics (4)</summary>

dd/raw images, EWF (EnCase), memory dumps
</details>

<details>
<summary>Mobile (6)</summary>

APK (Android), IPA (iOS), DEX (Dalvik bytecode)
</details>

---

## Installation

### Requirements

- Python 3.8+
- GCC (optional but strongly recommended for 10-50x performance)

### Quick start

```bash
git clone https://github.com/z0rhack/xcarver.git
cd xcarver
python3 carver.py --help
```

The C scanner compiles automatically on first run if GCC is available. No pip install needed.

### Optional: EnCase E01 support

```bash
pip install pyewf
```

### Kali Linux / Debian

```bash
# Coming soon via apt — see packaging section below
# For now:
git clone https://github.com/z0rhack/xcarver.git /opt/xcarver
echo 'alias xcarver="python3 /opt/xcarver/carver.py"' >> ~/.zshrc
```

---

## Usage

### List available devices

```bash
sudo python3 carver.py --list-devices
```

### List all supported file types

```bash
python3 carver.py --list-types
```

---

## Scenarios

### Scenario 1 — Recover deleted files from a USB drive

The most common use case: someone deleted files from a USB key and wants them back.

```bash
sudo python3 carver.py /dev/sdb --output ./usb_recovered/
```

xCarver will:
1. Detect the filesystem (FAT32, exFAT, NTFS...)
2. Recover deleted entries with original filenames and folder structure
3. Raw-carve the unallocated space for anything not found by the FS parser
4. Deduplicate results between both engines
5. Generate a JSON report

Output structure:
```
usb_recovered/
├── fs_recovered/          ← files with original names & paths
│   ├── Documents/
│   │   └── rapport.pdf
│   └── Photos/
│       └── vacances.jpg
├── raw/                   ← files found by raw carving
│   ├── jpeg/
│   ├── pdf/
│   └── ...
└── carving_report.json
```

### Scenario 2 — Carve a disk image (forensic investigation)

```bash
python3 carver.py disk_image.dd --output ./evidence/ --threads 8
```

For specific file types only:

```bash
python3 carver.py disk_image.dd --types jpeg,pdf,sqlite --output ./evidence/
```

For a full category:

```bash
python3 carver.py disk_image.dd --types document,image --output ./evidence/
```

### Scenario 3 — Large drive, interrupted session (resume)

For very large drives (1TB+), carving can take hours. If interrupted, resume where it left off:

```bash
# First run
sudo python3 carver.py /dev/sda --output ./carve_sda/ --resume

# If interrupted, same command resumes automatically
sudo python3 carver.py /dev/sda --output ./carve_sda/ --resume
```

### Scenario 4 — Skip encrypted partitions (BitLocker, VeraCrypt...)

Encrypted zones produce enormous numbers of false positives. Skip them:

```bash
python3 carver.py disk.dd --entropy-skip --output ./carve/
```

xCarver computes Shannon entropy per 512-byte block. Blocks above the threshold (typically >7.8 bits/byte) are skipped, drastically reducing false positives on encrypted or compressed data.

### Scenario 5 — CTF challenge / steganography analysis

CTF mode generates an entropy heatmap (HTML) and detects polyglot files and overlays:

```bash
python3 carver.py challenge.bin --ctf --output ./ctf_analysis/
```

Output includes:
- `entropy_heatmap.html` — visual entropy map of the entire image
- `polyglots.json` — files with multiple valid headers detected
- `overlays.json` — data appended after valid file footers

### Scenario 6 — FS-only recovery (fast, names preserved)

When you only want the FS-aware recovery and don't need raw carving:

```bash
python3 carver.py /dev/sdc --fs-only --output ./quick_recovery/
```

Significantly faster since it only parses filesystem metadata.

### Scenario 7 — Raw carving only (heavily damaged filesystem)

When the filesystem is destroyed and FS-aware recovery won't help:

```bash
python3 carver.py disk.img --raw-only --output ./raw_carved/
```

### Scenario 8 — EnCase/E01 forensic image

```bash
# Requires: pip install pyewf
python3 carver.py evidence.E01 --output ./case_output/
```

### Scenario 9 — Recursive archive extraction

Extracts files found inside ZIP, GZIP, BZIP2 archives recursively:

```bash
python3 carver.py image.dd --recursive --output ./deep_carve/
```

Found archives are automatically decompressed and their contents carved.

### Scenario 10 — Custom signatures (extend with your own types)

Create a JSON file with custom signatures:

```json
[
  {
    "name": "myformat",
    "ext": "mfmt",
    "header": "4d59464d54",
    "footer": "454e44",
    "max_size": 10485760,
    "min_size": 64,
    "category": "custom",
    "description": "My custom file format"
  }
]
```

```bash
python3 carver.py image.dd --sig-dir ./my_sigs/ --output ./carve/
```

### Scenario 11 — SSD / Advanced Format drives (4K sectors)

```bash
python3 carver.py /dev/nvme0n1 --sector-align --sector-size 4096 --output ./ssd_carve/
```

### Scenario 12 — RAM dump / memory forensics

```bash
python3 carver.py memory.mem --raw-only --types executable,document,image --output ./mem_carve/
```

### Scenario 13 — Limit output per file type (triage)

When you only need a sample of each type, not thousands of files:

```bash
python3 carver.py disk.dd --max-per-type 100 --output ./triage/
```

### Scenario 14 — No GCC available (pure Python fallback)

```bash
python3 carver.py image.dd --no-compile --output ./carve/
```

Warning: pure Python mode is 10-50x slower than the C scanner.

---

## Performance

| Mode | Typical speed |
|------|--------------|
| C scanner (GCC, 8 threads) | 800 MB/s – 2 GB/s (I/O bound) |
| C scanner (GCC, 1 thread) | 300 MB/s – 600 MB/s |
| Pure Python fallback | 20 MB/s – 60 MB/s |

The C scanner uses a persistent Aho-Corasick automaton: it is built once at startup and reused for every chunk — O(data) per scan, not O(patterns × data).

---

## Architecture

```
carver.py          Main orchestrator, CLI, report engine
  └── SourceReader     Opens images, raw devices, E01, RAM dumps
  └── PersistentScanner  Wraps C handle (xc_create/xc_scan/xc_free)
  └── Session          Session persistence for --resume
  └── carve_fs()       Phase 1: FS-aware recovery
  └── carve_raw()      Phase 2: Raw carving (multithreaded)

fs_parser.py       Filesystem parsers (FAT/NTFS/ext4/HFS+/APFS/...)
  └── parse_filesystem()    Detects FS type, recovers deleted entries
  └── reconstruct_file()    Follows cluster chains to rebuild files

signatures.py      119 file type definitions + structural validators
  └── SigDef             (name, ext, header, footer, min_size, max_size, validator)
  └── get_signatures()   Filter by type/category

scanner.c          High-performance C scanning engine
  └── xc_create()    Build Aho-Corasick automaton (once)
  └── xc_scan()      Multi-threaded scan (O(n) per chunk)
  └── xc_free()      Release handle
```

**Data flow:**

```
Source (device/image/E01)
  → FS-aware parser    → deleted entries with original names
  → Raw carver         → files by byte signature (C/multithreaded)
  → SHA256 dedup       → merge, remove duplicates
  → Output             → organized by type + JSON report
```

---

## Options reference

```
positional:
  source                    Image file, raw device, or E01

output:
  -o, --output DIR          Output directory (default: ./carved)

filtering:
  -t, --types TYPES         Comma-separated types or categories
                            Examples: jpeg,pdf  |  image  |  document,archive
                            Use --list-types for all available values

modes:
  --fs-only                 FS-aware recovery only (no raw carving)
  --raw-only                Raw carving only (no FS parsing)
  --ctf                     CTF mode: entropy heatmap + polyglot detection
  --recursive               Extract files inside recovered archives

performance:
  --threads N               Number of threads (default: auto, max 6)
  --chunk-size MB           Chunk size in MB (default: 64)
  --no-compile              Force pure Python mode (no C compilation)

advanced:
  --resume                  Resume a previous session
  --entropy-skip            Skip high-entropy zones (encrypted/compressed)
  --sector-align            Align offsets to sector boundaries
  --sector-size N           Sector size for --sector-align (default: 512)
  --max-per-type N          Max files per type, 0=unlimited (default: 0)
  --sig-dir DIR             Directory of additional JSON signatures

info:
  --list-devices            List available storage devices
  --list-types              List all supported file types and categories
```

---

## Output format

### Directory structure

```
output/
├── fs_recovered/           FS-aware results (original names & paths)
│   └── <original tree>
├── raw/                    Raw carving results
│   ├── jpeg/
│   ├── pdf/
│   ├── sqlite/
│   └── ...
├── recursive/              Files extracted from recovered archives
└── carving_report.json     Full statistics report
```

### carving_report.json

```json
{
  "source": "/dev/sdb",
  "size": 32010928128,
  "elapsed_s": 47.3,
  "speed_bps": 676869120,
  "fs": {
    "fs_type": "FAT32",
    "found": 142,
    "recovered": 138,
    "failed": 4
  },
  "raw": {
    "jpeg": 87,
    "pdf": 12,
    "sqlite": 3,
    "hits_raw": 1243,
    "invalid": 156,
    "too_small": 34,
    "dedup": 41
  }
}
```

---

## Building standalone executables

### Linux

```bash
gcc -O3 -march=native -shared -fPIC -pthread -o scanner.so scanner.c
pip install pyinstaller
pyinstaller --onefile --add-binary "scanner.so:." --add-data "scanner.c:." carver.py
# → dist/carver
```

### Windows (MinGW)

```bash
gcc -O3 -shared -o scanner.dll scanner.c
pip install pyinstaller
pyinstaller --onefile --add-binary "scanner.dll;." carver.py
# → dist/carver.exe
```

### macOS

```bash
gcc -O3 -shared -fPIC -o scanner.dylib scanner.c
pip install pyinstaller
pyinstaller --onefile --add-binary "scanner.dylib:." carver.py
# → dist/carver
```

---

## Contributing

Contributions welcome. Open issues, suggest new signatures, or submit pull requests.

When adding a signature to `signatures.py`:
- Provide `header` (byte sequence), `footer` if applicable
- Set realistic `min_size` and `max_size`
- Add a structural `validator` function if the format has verifiable fields (CRC, dimensions, magic constants)
- Test against real files, not just crafted ones

---

## Legal notice

xCarver is intended for authorized forensic investigation, data recovery on your own devices, security research, and CTF competitions. Do not use it on devices you do not own or have explicit authorization to analyze. The authors accept no liability for misuse.

---

## License

MIT — see [LICENSE](LICENSE)
