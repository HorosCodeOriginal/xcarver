# HorosCarver — Standalone Build Guide

**Produkt:** HorosCarver · **Firma:** HorosCode

## Voraussetzungen

| Tool | Mindestversion | Zweck |
|------|---------------|-------|
| .NET SDK | 9.0 | Build + Publish |
| Python | 3.10+ | Carver-Engine (`carver.py`) |
| GCC / MinGW (optional) | — | C-Scanner neu kompilieren (`scanner.c`) |

> Die vorkompilierte `scanner.dll` + `libwinpthread-1.dll` werden automatisch neben die EXE kopiert.

## Standalone-Build (Windows WinExe, Self-Contained)

```powershell
cd HorosCarver

dotnet publish -c Release `
    -r win-x64 `
    --self-contained true `
    -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -o publish\win-x64
```

Die fertige Anwendung liegt danach unter `HorosCarver\publish\win-x64\`:

```
HorosCarver.exe        ← Haupt-Executable
carver.py              ← Python-Engine
signatures.py
fs_parser.py
scanner.c              ← Quellcode (Referenz)
scanner.dll            ← Kompilierter C-Scanner
libwinpthread-1.dll    ← GCC-Laufzeit für scanner.dll
```

## Starten ohne Entwicklungsumgebung

```powershell
# Python muss im PATH sein
python --version

# Direkt starten
.\publish\win-x64\HorosCarver.exe
```

## Hinweis zu Python

HorosCarver ruft `python` als Subprocess auf. Auf Zielsystemen ohne Python-Installation muss entweder:
- Python zum System-PATH hinzugefügt werden, **oder**
- der Python-Pfad in `CarverService.cs` → `FileName` angepasst werden.

## Entwickler-Build (schnell, ohne Self-Contained)

```powershell
dotnet build -c Debug
dotnet run
```
