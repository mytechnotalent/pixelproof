# 🔍 PixelProof

**Detect fake, AI-generated, and Photoshopped images in seconds.**

PixelProof is a forensic-grade image analysis toolkit that exposes manipulation through metadata inspection, Error Level Analysis (ELA), noise profiling, and more — all from the command line.

**AUTHOR:** [Kevin Thomas](ket189@pitt.edu)

**CREATION DATE:** January 19, 2026  
**UPDATE DATE:** February 28, 2026

![Python](https://img.shields.io/badge/python-3.9+-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Pillow](https://img.shields.io/badge/Pillow-powered-yellow?logo=python)

---

## What It Detects

| Check                         | What It Finds                                                                                         |
| ----------------------------- | ----------------------------------------------------------------------------------------------------- |
| **EXIF Metadata**             | Missing camera info, stripped timestamps, absent GPS — signs the image didn't come from a real camera |
| **Photoshop Traces**          | Adobe 8BIM resource blocks and scrubbed caption digests embedded in file headers                      |
| **Error Level Analysis**      | Regions that compress differently from the rest — indicates pasting, cloning, or compositing          |
| **Noise Consistency**         | Different noise levels across regions — a hallmark of images stitched from multiple sources           |
| **Color Channel Correlation** | Abnormal R/G/B relationships that can indicate AI generation or heavy processing                      |
| **Edge Density**              | Unbalanced edge distribution that can reveal composited boundaries                                    |
| **JPEG Compression**          | Quantization table analysis to detect multiple re-saves                                               |

---

## Quick Start

### Install

```bash
# Clone the repo
git clone https://github.com/mytechnotalent/pixelproof.git
cd pixelproof

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install
pip install .
```

### Run a Quick Scan

```bash
python pixelproof.py photo.jpg
```

Output:
```
============================================================
  PIXELPROOF — Quick Forensic Metadata Scan
  File: photo.jpg
============================================================

  ⚠ FLAGS (3)
  ----------------------------------------
    ‣ NO CAMERA HARDWARE INFO — no Make, Model, Lens, ISO, etc.
    ‣ PHOTOSHOP RESOURCE BLOCK detected in file headers
    ‣ NO TIMESTAMP — real camera photos have date/time

============================================================
  🟡 SUSPICIOUS
============================================================
```

### Run a Deep Analysis (9 passes)

```bash
python deep_analysis.py suspect.jpg
```

This runs all forensic checks and saves:
- `suspect_ELA.png` — ELA visualization highlighting manipulated regions
- `suspect_REPORT.md` — full Markdown forensic report

### Generate a PDF Report

```bash
# Install PDF dependencies
pip install ".[pdf]"
```

#### macOS

WeasyPrint needs system libraries installed via Homebrew:

```bash
brew install pango glib cairo gobject-introspection
```

On macOS, the dynamic linker doesn't search Homebrew's library path by default. Set it before running:

```bash
export DYLD_LIBRARY_PATH="/opt/homebrew/lib"
python deep_analysis.py suspect.jpg --pdf
```

Or inline on a single command:

```bash
DYLD_LIBRARY_PATH="/opt/homebrew/lib" python deep_analysis.py suspect.jpg --pdf
```

> **Tip:** Add `export DYLD_LIBRARY_PATH="/opt/homebrew/lib"` to your `~/.zshrc` to make it permanent.

#### Windows

WeasyPrint requires GTK libraries. Install them via [MSYS2](https://www.msys2.org/):

1. Download and install MSYS2 from https://www.msys2.org/
2. Open the MSYS2 UCRT64 terminal and run:
   ```bash
   pacman -S mingw-w64-ucrt-x86_64-pango
   ```
3. Add the MSYS2 binary path to your system `PATH`:
   ```
   C:\msys64\ucrt64\bin
   ```
4. Restart your terminal / IDE, then:
   ```bash
   python deep_analysis.py suspect.jpg --pdf
   ```

> **Tip:** If you see `cannot load library 'libgobject-2.0-0'` or similar, the MSYS2 `bin` directory is not on your `PATH`.

#### Linux

Most distributions have the required libraries available via the system package manager:

```bash
# Debian / Ubuntu
sudo apt install libpango-1.0-0 libpangoft2-1.0-0 libpangocairo-1.0-0

# Fedora
sudo dnf install pango

# Arch
sudo pacman -S pango
```

No extra environment variables are needed on Linux.

---

Once the system libraries are in place, add `--pdf` to any deep analysis:

```bash
python deep_analysis.py suspect.jpg --pdf
```

This produces `suspect_REPORT.pdf` alongside the Markdown report — one command, one image, full pipeline.

---

## How It Works

### Error Level Analysis (ELA)

ELA resaves the image at a known JPEG quality and computes the pixel-by-pixel difference. In an unedited photo, error levels are uniform. Edited regions — pasted objects, cloned areas, AI-generated elements — compress differently and appear as **bright spots** in the ELA output.

### Noise Profiling

Real camera sensors produce consistent noise across the entire frame. When parts of an image come from different sources (compositing, AI inpainting), they carry **different noise signatures**. PixelProof measures noise variance across a grid and flags inconsistencies.

### Metadata Forensics

Every phone and camera writes dozens of EXIF tags — Make, Model, ISO, shutter speed, GPS, timestamps. Fake images typically have **none of these**, or contain Adobe Photoshop resource blocks (8BIM signatures) proving the image was processed in editing software.

---

## Project Structure

```
pixelproof/
├── pixelproof.py      # Quick metadata + Photoshop scan
├── deep_analysis.py   # Full 9-pass forensic analysis
├── generate_pdf.py    # Markdown → PDF report generator
├── pyproject.toml     # Package config & dependencies
├── LICENSE            # MIT
└── README.md          # You are here
```

---

## Examples

### Quick scan a suspicious photo
```bash
python pixelproof.py suspect.jpg
```

### Full forensic deep dive
```bash
python deep_analysis.py suspect.jpg
# Outputs: suspect_ELA.png + suspect_REPORT.md
```

### Full analysis with PDF report
```bash
python deep_analysis.py suspect.jpg --pdf
# Outputs: suspect_ELA.png + suspect_REPORT.md + suspect_REPORT.pdf
```

---

## Requirements

- **Python 3.9+**
- **Pillow** (installed automatically)
- **weasyprint + markdown2** (optional, for PDF generation — `pip install ".[pdf]"`)
- **System libraries for PDF** (only needed if using `--pdf`):
  - **macOS:** `brew install pango glib cairo gobject-introspection` + set `DYLD_LIBRARY_PATH="/opt/homebrew/lib"`
  - **Windows:** MSYS2 with `pacman -S mingw-w64-ucrt-x86_64-pango` + add `C:\msys64\ucrt64\bin` to `PATH`
  - **Linux:** `sudo apt install libpango-1.0-0 libpangoft2-1.0-0 libpangocairo-1.0-0` (Debian/Ubuntu)

---

## Use Cases

- **Verify photos** sent to you — are they real or fabricated?
- **Legal/insurance** — document forensic evidence of image manipulation
- **Journalism** — verify source images before publication
- **Social media** — check if a viral photo is AI-generated or Photoshopped
- **Personal safety** — detect fake photos of yourself

---

## Contributing

PRs welcome. If you find a new detection technique or a false positive, open an issue.

---

## License

MIT — see [LICENSE](LICENSE).
