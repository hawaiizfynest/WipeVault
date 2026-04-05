# 🔒 WipeVault

[![Build WipeVault](https://github.com/HawaiizFynest/wipevault/actions/workflows/build.yml/badge.svg)](https://github.com/HawaiizFynest/wipevault/actions/workflows/build.yml)
[![GitHub release (latest by tag)](https://img.shields.io/github/v/release/HawaiizFynest/wipevault?label=latest%20release&color=00C2FF)](https://github.com/HawaiizFynest/wipevault/releases/latest)
[![GitHub all releases](https://img.shields.io/github/downloads/HawaiizFynest/wipevault/total?color=00FF9C&label=total%20downloads)](https://github.com/HawaiizFynest/wipevault/releases)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)](https://github.com/HawaiizFynest/wipevault/releases/latest)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Standard](https://img.shields.io/badge/wipe%20standard-DoD%205220.22--M-red)](https://github.com/HawaiizFynest/wipevault#-wipe-standard)

**DoD 5220.22-M Secure Drive Erasure Tool**

WipeVault is a cross-platform desktop application that performs certified, auditable three-pass data sanitization on hard drives, SSDs, USB drives, and NVMe drives — compliant with the U.S. Department of Defense 5220.22-M standard. Upon completion, it generates a professional PDF certificate of erasure documenting the serial number, drive details, wipe method, pass results, and technician/company information.

---

## ✨ Features

- **DoD 5220.22-M 3-Pass Wipe** — Pass 1 writes binary zeros (0x00), Pass 2 writes binary ones (0xFF), Pass 3 writes cryptographically random data followed by post-wipe verification
- **Broad Drive Support** — Internal HDDs, SATA SSDs, NVMe drives, and external USB storage
- **Automatic Drive Detection** — Scans and lists all connected drives with model, serial number, size, interface type, and connection type (Internal / External)
- **Simulation Mode** — Safely rehearse a wipe without writing a single byte; great for training or testing
- **PDF Certificate of Erasure** — Generated on wipe completion; includes drive serial, wipe method, pass results, timestamps, and optional company branding
- **Company Branding** — Optionally add your company name, website, technician name, and time zone to the certificate; defaults to WipeVault branding if left blank
- **Real-Time Wipe Log** — Live console-style output showing sector block progress for each pass
- **Cross-Platform** — Windows, macOS, Linux

---

## 🖥️ Screenshots

> *(Screenshots will be added here after first stable release)*

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10 or higher
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/HawaiizFynest/wipevault.git
cd wipevault

# Install dependencies
pip install -r requirements.txt
```

### Running the App

**Windows:**
```
WipeVault.bat
```
or
```
python run.py
```

**macOS / Linux:**
```bash
bash wipevault.sh
```
or
```bash
python3 run.py
```

> **⚠️ Important:** On Linux and macOS, performing a real (non-simulated) wipe requires running with `sudo` since writing directly to block devices requires elevated privileges. On Windows, run as Administrator.

---

## 📄 Certificate of Erasure

After a wipe completes, click **Generate Certificate** to produce a PDF report. You will be prompted to optionally provide:

| Field | Description |
|---|---|
| Company Name | Your organization's name |
| Website | Your company URL |
| Technician | Name of the person performing the wipe |
| Time Zone | Time zone for the timestamp on the certificate |

If left blank, the certificate defaults to **WipeVault** branding.

Certificates are saved to `~/WipeVault_Certs/` and named with the drive serial number and timestamp for easy archiving.

---

## 🔬 Wipe Standard

WipeVault implements the **DoD 5220.22-M** standard (U.S. Department of Defense National Industrial Security Program Operating Manual):

| Pass | Pattern | Description |
|---|---|---|
| 1 | `0x00` | Overwrite entire drive with binary zeros |
| 2 | `0xFF` | Overwrite entire drive with binary ones |
| 3 | Random | Overwrite with cryptographically random data |
| ✓ | Verify | Post-wipe sector verification scan |

This standard ensures that data cannot be recovered through conventional or forensic means.

---

## 🛠️ Building a Standalone Executable

WipeVault includes a PyInstaller spec file for building a single distributable binary.

```bash
pip install pyinstaller
python -m PyInstaller WipeVault.spec
```

Output is placed in the `dist/` folder:
- **Windows:** `dist/WipeVault.exe`
- **macOS:** `dist/WipeVault.app`
- **Linux:** `dist/WipeVault`

---

## 📁 Project Structure

```
wipevault/
├── src/
│   └── wipevault.py          # Main application (UI + wipe engine + certificate)
├── run.py                    # Cross-platform launcher script
├── WipeVault.bat             # Windows quick-launch
├── wipevault.sh              # macOS/Linux quick-launch
├── WipeVault.spec            # PyInstaller build spec
├── requirements.txt          # Python dependencies
├── .gitignore
└── README.md
```

---

## 🔮 Planned Features (Roadmap)

- [ ] Gutmann 35-pass wipe mode
- [ ] NIST 800-88 Clear and Purge standards
- [ ] ATA Secure Erase (NVMe and SATA)
- [ ] Batch wipe multiple drives simultaneously
- [ ] Certificate signing and tamper detection
- [ ] Custom certificate logo/branding upload
- [ ] Wipe history log with searchable archive
- [ ] Product key / device-ID licensing system
- [ ] Encrypted application binary distribution

---

## ⚖️ License

Copyright © 2025 WipeVault. All rights reserved.

This software is provided free of charge for personal and commercial use in its current form. Redistribution, modification, resale, or sublicensing of the source code or compiled binaries without explicit written permission from the author is prohibited.

A full commercial license with additional features, enterprise support, and distribution rights is planned for a future release.

---

## ⚠️ Disclaimer

WipeVault is a powerful data destruction tool. Wiped data **cannot be recovered**. Always verify you have selected the correct drive before initiating a live wipe. The authors accept no liability for accidental data loss. Use Simulation Mode to familiarize yourself with the application before performing any real wipes.

---

*WipeVault — Wipe with confidence. Certify with proof.*
