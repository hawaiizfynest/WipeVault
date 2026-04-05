# 🔒 WipeVault

![Build](https://img.shields.io/badge/build-passing-brightgreen?logo=github)
![Release](https://img.shields.io/badge/release-v2.1.2-00C2FF)
![Downloads](https://img.shields.io/badge/downloads-0-00FF9C)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)
![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)
![Standard](https://img.shields.io/badge/wipe%20standard-DoD%205220.22--M-red)

**DoD 5220.22-M Secure Drive Erasure Tool**

WipeVault is a cross-platform desktop application that performs certified, auditable three-pass data sanitization on hard drives, SSDs, USB drives, and NVMe drives — compliant with the U.S. Department of Defense 5220.22-M standard. Upon completion, it generates a professional PDF certificate of erasure documenting the serial number, drive details, wipe method, pass results, and technician/company information.

---

## ✨ Features

- **6 Wipe Standards** — Choose the right method for your compliance or security requirement via a simple dropdown
- **Broad Drive Support** — Internal HDDs, SATA SSDs, NVMe drives, and external USB storage
- **Automatic Drive Detection** — Scans and lists all connected drives with model, serial number, size, interface type, and connection type (Internal / External)
- **Simulation Mode** — Safely rehearse a wipe without writing a single byte; great for training or testing
- **PDF Certificate of Erasure** — Generated on wipe completion; includes drive serial, wipe method, pass results, timestamps, and optional company branding
- **Company Branding** — Optionally add your company name, website, technician name, and time zone to the certificate; defaults to WipeVault branding if left blank
- **Real-Time Wipe Log** — Live console-style output showing sector block progress for each pass
- **Cross-Platform** — Windows, macOS, Linux

---

## 🖥️ Screenshots

**Main Window — Drive Detection & Method Selection**
![WipeVault Main Window](assets/screenshots/screenshot_main.png)

**Wipe Method Dropdown — All 6 Standards**
![Wipe Method Dropdown](assets/screenshots/screenshot_dropdown.png)

**Active Wipe — DoD 5220.28-STD 7-Pass In Progress**
![Wipe In Progress](assets/screenshots/screenshot_wiping.png)

**Wipe Complete — Certificate Ready**
![Wipe Complete](assets/screenshots/screenshot_complete.png)

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

## 🔬 Wipe Standards

WipeVault v2 supports six industry-recognized data sanitization standards, selectable from a dropdown before each wipe:

| Method | Passes | Description |
|---|---|---|
| **DoD 5220.22-M** | 3 | U.S. DoD standard: zeros → ones → random + verify |
| **DoD 5220.28-STD** | 7 | U.S. Air Force standard: alternating fixed patterns + random passes |
| **Gutmann Method** | 35 | Peter Gutmann's method designed to defeat magnetic force microscopy on older drives |
| **NIST SP 800-88** | 1 | NIST Purge: single random overwrite with read-back verification |
| **Zero Fill** | 1 | Single pass of 0x00 — fast, suitable for general reuse |
| **ATA Secure Erase** | 1 | Firmware-level erase command; fastest and most thorough for SSDs and NVMe |

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

### ✅ Completed
- [x] DoD 5220.22-M 3-pass wipe
- [x] DoD 5220.28-STD 7-pass wipe
- [x] Gutmann 35-pass wipe mode
- [x] NIST SP 800-88 Purge standard
- [x] Zero Fill single-pass wipe
- [x] ATA Secure Erase (NVMe and SATA firmware command)
- [x] Wipe method selector dropdown
- [x] PDF certificate of erasure with company branding
- [x] Real-time wipe log with per-pass progress
- [x] Simulation mode (dry run)
- [x] Cross-platform builds via GitHub Actions (Windows, macOS, Linux)
- [x] Clear partition table (MBR/GPT) after wipe
- [x] Initialize drive with GPT or MBR after wipe

### 🔜 Coming Soon
- [ ] NIST SP 800-88 Clear standard (in addition to Purge)
- [ ] Batch wipe — select and wipe multiple drives simultaneously
- [ ] Wipe history log with searchable archive
- [ ] Custom certificate logo / company branding image upload
- [ ] Certificate signing and tamper-evident verification

### 🔐 Future (Commercial Release)
- [ ] Product key / device-ID locking system
- [ ] Secure licensing database integration
- [ ] Encrypted application binary distribution
- [ ] Enterprise reporting and audit export (CSV / JSON)
- [ ] White-label certificate theming for IT service companies

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
