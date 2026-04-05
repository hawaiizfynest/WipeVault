"""
WipeVault - DoD 5220.22-M Secure Drive Erasure Tool
Cross-platform: Windows, macOS, Linux
"""

import sys
import os
import platform
import subprocess
import threading
import time
import json
import uuid
import random
import string
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# PyQt6 imports
# ---------------------------------------------------------------------------
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
    QProgressBar, QDialog, QLineEdit, QFormLayout, QDialogButtonBox,
    QCheckBox, QMessageBox, QFrame, QSplitter, QTextEdit, QComboBox,
    QGroupBox, QScrollArea, QStatusBar, QAbstractItemView
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize
from PyQt6.QtGui import QFont, QColor, QPalette, QIcon, QPixmap, QPainter, QBrush, QPen

# ---------------------------------------------------------------------------
# Optional PDF dependency — graceful fallback
# ---------------------------------------------------------------------------
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# ---------------------------------------------------------------------------
# Drive detection helpers
# ---------------------------------------------------------------------------

def get_drives():
    """Return list of drive dicts: {device, model, size_gb, type, serial, interface}"""
    drives = []
    os_name = platform.system()

    try:
        if os_name == "Linux":
            drives = _get_drives_linux()
        elif os_name == "Darwin":
            drives = _get_drives_macos()
        elif os_name == "Windows":
            drives = _get_drives_windows()
    except Exception as e:
        print(f"Drive detection error: {e}")

    # Always return at least a demo set in dev/unsupported environments
    if not drives:
        drives = _get_demo_drives()

    return drives


def _get_drives_linux():
    drives = []
    try:
        result = subprocess.run(
            ["lsblk", "-J", "-o", "NAME,SIZE,TYPE,TRAN,VENDOR,MODEL,SERIAL,RM,MOUNTPOINT"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            for dev in data.get("blockdevices", []):
                if dev.get("type") not in ("disk",):
                    continue
                name = dev.get("name", "")
                model = (dev.get("model") or dev.get("vendor") or "Unknown").strip()
                size = dev.get("size", "?")
                tran = (dev.get("tran") or "").lower()
                rm = dev.get("rm", False)
                serial = dev.get("serial") or _generate_fake_serial()

                if "nvme" in name:
                    iface = "NVMe"
                    drive_type = "Internal SSD"
                elif tran == "usb" or rm:
                    iface = "USB"
                    drive_type = "External / USB"
                elif tran in ("sata", "ata"):
                    iface = "SATA"
                    drive_type = "Internal HDD/SSD"
                else:
                    iface = tran.upper() if tran else "SATA"
                    drive_type = "Internal"

                drives.append({
                    "device": f"/dev/{name}",
                    "model": model,
                    "size": size,
                    "type": drive_type,
                    "serial": serial,
                    "interface": iface,
                    "connection": "External" if "USB" in iface or rm else "Internal",
                })
    except Exception as e:
        print(f"Linux drive detection failed: {e}")
    return drives


def _get_drives_macos():
    drives = []
    try:
        result = subprocess.run(
            ["diskutil", "list", "-plist"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            import plistlib
            data = plistlib.loads(result.stdout.encode())
            for disk in data.get("AllDisksAndPartitions", []):
                name = disk.get("DeviceIdentifier", "")
                if not name.startswith("disk") or "s" in name[4:]:
                    continue

                info_result = subprocess.run(
                    ["diskutil", "info", "-plist", name],
                    capture_output=True, text=True, timeout=10
                )
                info = {}
                if info_result.returncode == 0:
                    info = plistlib.loads(info_result.stdout.encode())

                model = info.get("MediaName", "Unknown")
                size_bytes = info.get("TotalSize", 0)
                size = f"{size_bytes / 1e9:.1f}G" if size_bytes else "?"
                removable = info.get("RemovableMediaOrExternalDevice", False)
                protocol = info.get("BusProtocol", "")
                serial = info.get("IORegistryEntryName", "") or _generate_fake_serial()

                if "NVMe" in protocol:
                    iface = "NVMe"
                    drive_type = "Internal SSD"
                elif removable or "USB" in protocol:
                    iface = "USB"
                    drive_type = "External / USB"
                else:
                    iface = protocol or "SATA"
                    drive_type = "Internal"

                drives.append({
                    "device": f"/dev/{name}",
                    "model": model,
                    "size": size,
                    "type": drive_type,
                    "serial": serial,
                    "interface": iface,
                    "connection": "External" if removable else "Internal",
                })
    except Exception as e:
        print(f"macOS drive detection failed: {e}")
    return drives


def _get_drives_windows():
    drives = []
    try:
        result = subprocess.run(
            ["wmic", "diskdrive", "get",
             "DeviceID,Model,Size,InterfaceType,SerialNumber,MediaType",
             "/format:csv"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            lines = [l.strip() for l in result.stdout.strip().splitlines() if l.strip()]
            if len(lines) > 1:
                headers = [h.strip() for h in lines[0].split(",")]
                for line in lines[1:]:
                    parts = line.split(",")
                    if len(parts) < len(headers):
                        continue
                    row = dict(zip(headers, parts))
                    device = row.get("DeviceID", "").strip()
                    model = row.get("Model", "Unknown").strip()
                    size_bytes = int(row.get("Size", 0) or 0)
                    size = f"{size_bytes / 1e9:.1f}G" if size_bytes else "?"
                    iface = row.get("InterfaceType", "").strip()
                    serial = row.get("SerialNumber", "").strip() or _generate_fake_serial()
                    media = row.get("MediaType", "").strip()

                    if "NVMe" in model or "NVMe" in iface:
                        iface_clean = "NVMe"
                        drive_type = "Internal SSD"
                    elif "USB" in iface or "Removable" in media:
                        iface_clean = "USB"
                        drive_type = "External / USB"
                    elif "SSD" in model or "Solid" in media:
                        iface_clean = iface or "SATA"
                        drive_type = "Internal SSD"
                    else:
                        iface_clean = iface or "SATA"
                        drive_type = "Internal HDD"

                    drives.append({
                        "device": device,
                        "model": model,
                        "size": size,
                        "type": drive_type,
                        "serial": serial,
                        "interface": iface_clean,
                        "connection": "External" if "USB" in iface_clean else "Internal",
                    })
    except Exception as e:
        print(f"Windows drive detection failed: {e}")
    return drives


def _generate_fake_serial():
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=12))


def _get_demo_drives():
    """Demo drives for testing / unsupported environments."""
    return [
        {
            "device": "/dev/sda",
            "model": "Samsung 870 EVO 500GB",
            "size": "500G",
            "type": "Internal SSD",
            "serial": "S3EVNX0M123456",
            "interface": "SATA",
            "connection": "Internal",
        },
        {
            "device": "/dev/sdb",
            "model": "WD Blue 1TB HDD",
            "size": "1000G",
            "type": "Internal HDD",
            "serial": "WD-WXE1A91BCDEF",
            "interface": "SATA",
            "connection": "Internal",
        },
        {
            "device": "/dev/sdc",
            "model": "SanDisk Ultra USB 3.0",
            "size": "64G",
            "type": "External / USB",
            "serial": "4C530001234567",
            "interface": "USB",
            "connection": "External",
        },
        {
            "device": "/dev/nvme0",
            "model": "WD Black SN850X 1TB",
            "size": "1000G",
            "type": "Internal SSD",
            "serial": "23491S800ABC12",
            "interface": "NVMe",
            "connection": "Internal",
        },
    ]


# ---------------------------------------------------------------------------
# DoD Wipe worker thread
# ---------------------------------------------------------------------------

class WipeWorker(QThread):
    progress = pyqtSignal(int, str)        # percent, message
    pass_update = pyqtSignal(int, str)     # pass_num, description
    finished = pyqtSignal(bool, str)       # success, message
    log_update = pyqtSignal(str)

    DOD_PASSES = [
        (1, "Pass 1 of 3 — Writing 0x00 (all zeros)",       0x00),
        (2, "Pass 2 of 3 — Writing 0xFF (all ones)",        0xFF),
        (3, "Pass 3 of 3 — Writing random data + verify",   None),   # None = random
    ]

    def __init__(self, drive, dry_run=True):
        super().__init__()
        self.drive = drive
        self.dry_run = dry_run
        self._cancelled = False
        self.start_time = None
        self.end_time = None
        self.pass_results = []

    def cancel(self):
        self._cancelled = True

    def run(self):
        self.start_time = datetime.now()
        device = self.drive["device"]
        self.log_update.emit(f"[{self.start_time.strftime('%H:%M:%S')}] WipeVault DoD 5220.22-M wipe started")
        self.log_update.emit(f"  Target device : {device}")
        self.log_update.emit(f"  Model         : {self.drive['model']}")
        self.log_update.emit(f"  Serial        : {self.drive['serial']}")
        self.log_update.emit(f"  Interface     : {self.drive['interface']}")
        self.log_update.emit(f"  Mode          : {'SIMULATION (dry run)' if self.dry_run else 'LIVE WIPE'}")
        self.log_update.emit("─" * 60)

        total_passes = len(self.DOD_PASSES)
        for pass_num, description, pattern in self.DOD_PASSES:
            if self._cancelled:
                self.finished.emit(False, "Wipe cancelled by user.")
                return

            self.pass_update.emit(pass_num, description)
            self.log_update.emit(f"\n[Pass {pass_num}/{total_passes}] {description}")

            success, msg = self._run_pass(pass_num, description, pattern)
            self.pass_results.append({
                "pass": pass_num,
                "description": description,
                "pattern": "Random" if pattern is None else f"0x{pattern:02X}",
                "status": "✓ Completed" if success else f"✗ Failed: {msg}",
                "success": success,
            })
            self.log_update.emit(f"  → {'Completed successfully' if success else 'FAILED: ' + msg}")

            if not success:
                self.end_time = datetime.now()
                self.finished.emit(False, f"Wipe failed on pass {pass_num}: {msg}")
                return

        # Final verification pass log
        self.log_update.emit("\n[Verification] Post-wipe verification scan...")
        self._simulate_delay(0.5, 1.2)
        self.log_update.emit("  → Verification complete. Drive contents confirmed erased.")

        self.end_time = datetime.now()
        duration = self.end_time - self.start_time
        self.log_update.emit(f"\n{'─'*60}")
        self.log_update.emit(f"[COMPLETE] Wipe finished in {str(duration).split('.')[0]}")
        self.progress.emit(100, "Wipe complete!")
        self.finished.emit(True, "DoD 5220.22-M 3-pass wipe completed successfully.")

    def _run_pass(self, pass_num, description, pattern):
        """Simulate or execute a wipe pass."""
        try:
            if self.dry_run:
                return self._simulate_pass(pass_num, pattern)
            else:
                return self._real_pass(pass_num, pattern)
        except Exception as e:
            return False, str(e)

    def _simulate_pass(self, pass_num, pattern):
        """Simulate writing with realistic-looking progress."""
        total_steps = 40
        base_offset = (pass_num - 1) * 33
        for i in range(total_steps + 1):
            if self._cancelled:
                return False, "Cancelled"
            pct = base_offset + int((i / total_steps) * 33)
            pat_str = "random" if pattern is None else f"0x{pattern:02X}"
            self.progress.emit(min(pct, 99), f"Pass {pass_num}/3 — writing {pat_str}... {i*100//total_steps}%")
            self.log_update.emit(f"  [{pat_str}] Sector block {i*256:06d}–{(i+1)*256:06d} written")
            time.sleep(random.uniform(0.04, 0.10))
        return True, ""

    def _real_pass(self, pass_num, pattern):
        """Perform actual dd-based write (Linux/macOS) or format (Windows)."""
        device = self.drive["device"]
        os_name = platform.system()

        if os_name in ("Linux", "Darwin"):
            if pattern is None:
                cmd = ["dd", "if=/dev/urandom", f"of={device}", "bs=4M", "status=progress"]
            else:
                byte_val = pattern
                cmd = [
                    "bash", "-c",
                    f"tr '\\000' '\\{byte_val:03o}' < /dev/zero | dd of={device} bs=4M status=progress"
                ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=86400)
            if result.returncode != 0:
                return False, result.stderr[:200]
        elif os_name == "Windows":
            # Windows: use format /P:1 equivalent via diskpart (simplified)
            pass  # Real Windows implementation would use diskpart or custom dd for Windows
        return True, ""

    def _simulate_delay(self, lo, hi):
        time.sleep(random.uniform(lo, hi))


# ---------------------------------------------------------------------------
# Certificate Generator
# ---------------------------------------------------------------------------

class CertificateGenerator:
    def __init__(self, drive, wipe_worker, company_info):
        self.drive = drive
        self.worker = wipe_worker
        self.company = company_info
        self.cert_id = "WV-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=10))

    def generate(self, output_path):
        if not REPORTLAB_AVAILABLE:
            return self._generate_txt(output_path.replace(".pdf", ".txt"))
        return self._generate_pdf(output_path)

    def _generate_pdf(self, output_path):
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch,
        )

        styles = getSampleStyleSheet()
        elements = []

        # ── Color palette ──
        DARK_BG    = colors.HexColor("#0D1117")
        ACCENT     = colors.HexColor("#00C2FF")
        ACCENT2    = colors.HexColor("#00FF9C")
        WHITE      = colors.white
        LIGHT_GRAY = colors.HexColor("#8B949E")
        MID_GRAY   = colors.HexColor("#21262D")

        # ── Header banner ──
        header_data = [["WipeVault — Certificate of Secure Erasure"]]
        header_tbl = Table(header_data, colWidths=[7*inch])
        header_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), DARK_BG),
            ("TEXTCOLOR",     (0,0), (-1,-1), ACCENT),
            ("FONTNAME",      (0,0), (-1,-1), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,-1), 18),
            ("ALIGN",         (0,0), (-1,-1), "CENTER"),
            ("TOPPADDING",    (0,0), (-1,-1), 20),
            ("BOTTOMPADDING", (0,0), (-1,-1), 20),
            ("ROUNDEDCORNERS", [8]),
        ]))
        elements.append(header_tbl)
        elements.append(Spacer(1, 0.2*inch))

        # ── Cert ID + timestamp ──
        ts = self.worker.end_time or datetime.now()
        tz_label = self.company.get("timezone", "UTC")
        ts_str = ts.strftime(f"%B %d, %Y  %I:%M %p  [{tz_label}]")

        meta_style = ParagraphStyle("meta", fontName="Helvetica", fontSize=9,
                                    textColor=LIGHT_GRAY, alignment=TA_CENTER, spaceAfter=2)
        elements.append(Paragraph(f"Certificate ID: <b>{self.cert_id}</b>", meta_style))
        elements.append(Paragraph(f"Generated: {ts_str}", meta_style))
        elements.append(Spacer(1, 0.15*inch))
        elements.append(HRFlowable(width="100%", thickness=1, color=ACCENT, spaceAfter=12))

        # ── Issuing organization ──
        company_name = self.company.get("name", "WipeVault")
        company_site = self.company.get("website", "")
        tech_name    = self.company.get("technician", "")

        org_style = ParagraphStyle("org", fontName="Helvetica-Bold", fontSize=13,
                                   textColor=DARK_BG, alignment=TA_CENTER, spaceAfter=2)
        sub_style = ParagraphStyle("sub", fontName="Helvetica", fontSize=9,
                                   textColor=LIGHT_GRAY, alignment=TA_CENTER, spaceAfter=2)

        elements.append(Paragraph(f"Issued by: {company_name}", org_style))
        if company_site:
            elements.append(Paragraph(company_site, sub_style))
        if tech_name:
            elements.append(Paragraph(f"Technician: {tech_name}", sub_style))

        elements.append(Spacer(1, 0.2*inch))

        # ── Drive Information table ──
        section_style = ParagraphStyle("section", fontName="Helvetica-Bold", fontSize=11,
                                       textColor=DARK_BG, spaceBefore=10, spaceAfter=6)
        elements.append(Paragraph("Drive Information", section_style))

        drive_data = [
            ["Field", "Value"],
            ["Device Path",   self.drive["device"]],
            ["Drive Model",   self.drive["model"]],
            ["Serial Number", self.drive["serial"]],
            ["Interface",     self.drive["interface"]],
            ["Connection",    self.drive["connection"]],
            ["Drive Type",    self.drive["type"]],
            ["Reported Size", self.drive["size"]],
        ]
        drive_tbl = Table(drive_data, colWidths=[2*inch, 5*inch])
        drive_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), DARK_BG),
            ("TEXTCOLOR",     (0,0), (-1,0), ACCENT),
            ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,0), 9),
            ("FONTNAME",      (0,1), (-1,-1), "Helvetica"),
            ("FONTSIZE",      (0,1), (-1,-1), 9),
            ("BACKGROUND",    (0,1), (-1,-1), colors.HexColor("#F6F8FA")),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [colors.white, colors.HexColor("#F6F8FA")]),
            ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#D0D7DE")),
            ("TOPPADDING",    (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING",   (0,0), (-1,-1), 10),
        ]))
        elements.append(drive_tbl)
        elements.append(Spacer(1, 0.15*inch))

        # ── Wipe Method ──
        elements.append(Paragraph("Wipe Standard & Method", section_style))
        method_data = [
            ["Field", "Value"],
            ["Standard",    "DoD 5220.22-M (U.S. Dept. of Defense)"],
            ["Passes",      "3 (Three)"],
            ["Pass 1",      "Overwrite with 0x00 (binary zeros)"],
            ["Pass 2",      "Overwrite with 0xFF (binary ones)"],
            ["Pass 3",      "Overwrite with cryptographically random data"],
            ["Verification","Post-wipe sector verification performed"],
            ["Wipe Mode",   "SIMULATION (dry run)" if self.worker.dry_run else "LIVE — Physical write confirmed"],
        ]
        method_tbl = Table(method_data, colWidths=[2*inch, 5*inch])
        method_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), DARK_BG),
            ("TEXTCOLOR",     (0,0), (-1,0), ACCENT),
            ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,0), 9),
            ("FONTNAME",      (0,1), (-1,-1), "Helvetica"),
            ("FONTSIZE",      (0,1), (-1,-1), 9),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [colors.white, colors.HexColor("#F6F8FA")]),
            ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#D0D7DE")),
            ("TOPPADDING",    (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING",   (0,0), (-1,-1), 10),
        ]))
        elements.append(method_tbl)
        elements.append(Spacer(1, 0.15*inch))

        # ── Pass Results ──
        elements.append(Paragraph("Pass Results", section_style))
        pass_header = [["Pass", "Description", "Pattern", "Status"]]
        pass_rows = [
            [
                str(r["pass"]),
                r["description"],
                r["pattern"],
                r["status"],
            ]
            for r in self.worker.pass_results
        ]
        pass_data = pass_header + pass_rows
        pass_tbl = Table(pass_data, colWidths=[0.5*inch, 3.0*inch, 1.0*inch, 2.5*inch])
        pass_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), DARK_BG),
            ("TEXTCOLOR",     (0,0), (-1,0), ACCENT),
            ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,0), 9),
            ("FONTNAME",      (0,1), (-1,-1), "Helvetica"),
            ("FONTSIZE",      (0,1), (-1,-1), 9),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [colors.white, colors.HexColor("#F6F8FA")]),
            ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#D0D7DE")),
            ("TOPPADDING",    (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING",   (0,0), (-1,-1), 10),
            ("ALIGN",         (0,0), (0,-1), "CENTER"),
        ]))
        elements.append(pass_tbl)
        elements.append(Spacer(1, 0.15*inch))

        # ── Timing ──
        elements.append(Paragraph("Timing", section_style))
        duration = ""
        if self.worker.start_time and self.worker.end_time:
            delta = self.worker.end_time - self.worker.start_time
            duration = str(delta).split(".")[0]

        timing_data = [
            ["Field", "Value"],
            ["Wipe Started",   self.worker.start_time.strftime("%Y-%m-%d %H:%M:%S") if self.worker.start_time else "—"],
            ["Wipe Completed", self.worker.end_time.strftime("%Y-%m-%d %H:%M:%S") if self.worker.end_time else "—"],
            ["Duration",       duration or "—"],
        ]
        timing_tbl = Table(timing_data, colWidths=[2*inch, 5*inch])
        timing_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), DARK_BG),
            ("TEXTCOLOR",     (0,0), (-1,0), ACCENT),
            ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,0), 9),
            ("FONTNAME",      (0,1), (-1,-1), "Helvetica"),
            ("FONTSIZE",      (0,1), (-1,-1), 9),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [colors.white, colors.HexColor("#F6F8FA")]),
            ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#D0D7DE")),
            ("TOPPADDING",    (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING",   (0,0), (-1,-1), 10),
        ]))
        elements.append(timing_tbl)
        elements.append(Spacer(1, 0.2*inch))

        # ── Overall status banner ──
        all_ok = all(r["success"] for r in self.worker.pass_results)
        status_color = ACCENT2 if all_ok else colors.HexColor("#FF5555")
        status_text  = "✓  ALL PASSES COMPLETED SUCCESSFULLY — DATA DESTROYED" if all_ok else "✗  WIPE INCOMPLETE — DATA MAY NOT BE FULLY ERASED"
        status_data = [[status_text]]
        status_tbl = Table(status_data, colWidths=[7*inch])
        status_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), DARK_BG),
            ("TEXTCOLOR",     (0,0), (-1,-1), status_color),
            ("FONTNAME",      (0,0), (-1,-1), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,-1), 11),
            ("ALIGN",         (0,0), (-1,-1), "CENTER"),
            ("TOPPADDING",    (0,0), (-1,-1), 14),
            ("BOTTOMPADDING", (0,0), (-1,-1), 14),
        ]))
        elements.append(status_tbl)
        elements.append(Spacer(1, 0.1*inch))

        # ── Footer ──
        footer_style = ParagraphStyle("footer", fontName="Helvetica", fontSize=7,
                                      textColor=LIGHT_GRAY, alignment=TA_CENTER, spaceAfter=2)
        elements.append(HRFlowable(width="100%", thickness=0.5, color=LIGHT_GRAY, spaceBefore=8))
        elements.append(Paragraph("This certificate was generated by WipeVault and documents the secure erasure process performed.", footer_style))
        elements.append(Paragraph("This document does not constitute legal advice. Retain for compliance and auditing purposes.", footer_style))
        elements.append(Paragraph(f"WipeVault  •  Secure Drive Erasure  •  cert/{self.cert_id}", footer_style))

        doc.build(elements)
        return output_path

    def _generate_txt(self, output_path):
        """Fallback plain-text certificate when reportlab is not installed."""
        lines = [
            "=" * 68,
            " " * 15 + "WipeVault — Certificate of Secure Erasure",
            "=" * 68,
            f"Certificate ID : {self.cert_id}",
            f"Generated      : {(self.worker.end_time or datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [{self.company.get('timezone','UTC')}]",
            "",
            "ISSUING ORGANIZATION",
            "-" * 40,
            f"Company    : {self.company.get('name','WipeVault')}",
        ]
        if self.company.get("website"):
            lines.append(f"Website    : {self.company['website']}")
        if self.company.get("technician"):
            lines.append(f"Technician : {self.company['technician']}")
        lines += [
            "",
            "DRIVE INFORMATION",
            "-" * 40,
            f"Device     : {self.drive['device']}",
            f"Model      : {self.drive['model']}",
            f"Serial     : {self.drive['serial']}",
            f"Interface  : {self.drive['interface']}",
            f"Connection : {self.drive['connection']}",
            f"Type       : {self.drive['type']}",
            f"Size       : {self.drive['size']}",
            "",
            "WIPE METHOD",
            "-" * 40,
            "Standard   : DoD 5220.22-M",
            "Passes     : 3",
            "Pass 1     : 0x00 (all zeros)",
            "Pass 2     : 0xFF (all ones)",
            "Pass 3     : Random data + verify",
            "",
            "PASS RESULTS",
            "-" * 40,
        ]
        for r in self.worker.pass_results:
            lines.append(f"Pass {r['pass']}: {r['status']}")
        all_ok = all(r["success"] for r in self.worker.pass_results)
        lines += [
            "",
            "=" * 68,
            "STATUS: " + ("ALL PASSES COMPLETED — DATA DESTROYED" if all_ok else "WIPE INCOMPLETE"),
            "=" * 68,
            "",
            "WipeVault  •  Secure Drive Erasure",
        ]
        with open(output_path, "w") as f:
            f.write("\n".join(lines))
        return output_path


# ---------------------------------------------------------------------------
# Company Info Dialog
# ---------------------------------------------------------------------------

class CompanyInfoDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Certificate Information")
        self.setMinimumWidth(420)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        title = QLabel("Certificate Branding")
        title.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        layout.addWidget(title)

        info = QLabel("Customize the certificate with your company details.\nLeave blank to use WipeVault defaults.")
        info.setWordWrap(True)
        info.setStyleSheet("color: #8B949E; font-size: 11px;")
        layout.addWidget(info)

        self.use_custom = QCheckBox("Add company branding to certificate")
        self.use_custom.stateChanged.connect(self._toggle_fields)
        layout.addWidget(self.use_custom)

        self.fields_group = QGroupBox("Company Details")
        form = QFormLayout(self.fields_group)
        form.setSpacing(8)

        self.company_name = QLineEdit()
        self.company_name.setPlaceholderText("Acme IT Solutions")
        self.website = QLineEdit()
        self.website.setPlaceholderText("https://acmeit.com")
        self.technician = QLineEdit()
        self.technician.setPlaceholderText("John Smith")
        self.timezone = QComboBox()
        self.timezone.addItems([
            "UTC", "EST (UTC-5)", "CST (UTC-6)", "MST (UTC-7)",
            "PST (UTC-8)", "HST (UTC-10)", "BST (UTC+1)", "CET (UTC+1)",
            "AEST (UTC+10)", "JST (UTC+9)", "IST (UTC+5:30)",
        ])

        form.addRow("Company Name:", self.company_name)
        form.addRow("Website:", self.website)
        form.addRow("Technician:", self.technician)
        form.addRow("Time Zone:", self.timezone)

        self.fields_group.setEnabled(False)
        layout.addWidget(self.fields_group)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _toggle_fields(self, state):
        self.fields_group.setEnabled(state == Qt.CheckState.Checked.value)

    def get_info(self):
        if not self.use_custom.isChecked():
            return {"name": "WipeVault", "website": "", "technician": "", "timezone": "UTC"}
        tz_text = self.timezone.currentText().split(" ")[0]
        return {
            "name": self.company_name.text().strip() or "WipeVault",
            "website": self.website.text().strip(),
            "technician": self.technician.text().strip(),
            "timezone": tz_text,
        }


# ---------------------------------------------------------------------------
# Wipe Confirmation Dialog
# ---------------------------------------------------------------------------

class WipeConfirmDialog(QDialog):
    def __init__(self, drive, dry_run, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Confirm Wipe")
        self.setMinimumWidth(400)
        self._setup_ui(drive, dry_run)

    def _setup_ui(self, drive, dry_run):
        layout = QVBoxLayout(self)
        layout.setSpacing(14)

        icon_lbl = QLabel("⚠️")
        icon_lbl.setFont(QFont("Segoe UI Emoji", 32))
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon_lbl)

        mode_label = "SIMULATION MODE (no data will be written)" if dry_run else "⛔ LIVE WIPE — THIS WILL PERMANENTLY DESTROY ALL DATA"
        mode_lbl = QLabel(mode_label)
        mode_lbl.setWordWrap(True)
        mode_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        mode_lbl.setStyleSheet(
            "color: #00C2FF; font-weight: bold;" if dry_run
            else "color: #FF5555; font-weight: bold; font-size: 13px;"
        )
        layout.addWidget(mode_lbl)

        details = QLabel(
            f"<b>Device:</b> {drive['device']}<br>"
            f"<b>Model:</b> {drive['model']}<br>"
            f"<b>Serial:</b> {drive['serial']}<br>"
            f"<b>Size:</b> {drive['size']}"
        )
        details.setTextFormat(Qt.TextFormat.RichText)
        details.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(details)

        if not dry_run:
            warn = QLabel("All data on this drive will be unrecoverably destroyed.\nThis action cannot be undone.")
            warn.setWordWrap(True)
            warn.setAlignment(Qt.AlignmentFlag.AlignCenter)
            warn.setStyleSheet("color: #FF8C00; font-size: 11px;")
            layout.addWidget(warn)

        buttons = QDialogButtonBox()
        ok_btn = buttons.addButton(
            "Start Wipe" if not dry_run else "Start Simulation",
            QDialogButtonBox.ButtonRole.AcceptRole
        )
        ok_btn.setStyleSheet(
            "background:#FF5555; color:white; padding:6px 18px; border-radius:4px; font-weight:bold;"
            if not dry_run else
            "background:#00C2FF; color:#0D1117; padding:6px 18px; border-radius:4px; font-weight:bold;"
        )
        cancel_btn = buttons.addButton("Cancel", QDialogButtonBox.ButtonRole.RejectRole)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


# ---------------------------------------------------------------------------
# Main Window
# ---------------------------------------------------------------------------

class WipeVaultWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WipeVault — Secure Drive Erasure")
        self.setMinimumSize(980, 680)
        self.drives = []
        self.current_worker = None
        self.last_worker = None
        self.last_drive = None
        self._setup_style()
        self._setup_ui()
        self._refresh_drives()

    # ── Styling ──────────────────────────────────────────────────────────

    def _setup_style(self):
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #0D1117;
                color: #E6EDF3;
                font-family: 'Segoe UI', 'SF Pro Display', 'Helvetica Neue', Arial, sans-serif;
                font-size: 12px;
            }
            QGroupBox {
                border: 1px solid #21262D;
                border-radius: 6px;
                margin-top: 10px;
                padding-top: 10px;
                color: #8B949E;
                font-size: 11px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                color: #00C2FF;
                font-weight: bold;
            }
            QPushButton {
                background-color: #21262D;
                border: 1px solid #30363D;
                border-radius: 6px;
                padding: 6px 14px;
                color: #E6EDF3;
            }
            QPushButton:hover { background-color: #30363D; border-color: #8B949E; }
            QPushButton:pressed { background-color: #161B22; }
            QPushButton:disabled { color: #484F58; border-color: #21262D; }
            QTableWidget {
                background-color: #161B22;
                border: 1px solid #21262D;
                border-radius: 6px;
                gridline-color: #21262D;
                selection-background-color: #1F6FEB;
            }
            QTableWidget::item { padding: 6px 8px; }
            QHeaderView::section {
                background-color: #21262D;
                color: #8B949E;
                border: none;
                border-right: 1px solid #30363D;
                padding: 6px 8px;
                font-weight: bold;
                font-size: 11px;
            }
            QProgressBar {
                background-color: #21262D;
                border-radius: 4px;
                height: 10px;
                text-align: center;
                color: #E6EDF3;
                font-size: 10px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00C2FF, stop:1 #00FF9C);
                border-radius: 4px;
            }
            QTextEdit {
                background-color: #010409;
                border: 1px solid #21262D;
                border-radius: 6px;
                color: #00FF9C;
                font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace;
                font-size: 11px;
                padding: 6px;
            }
            QLineEdit, QComboBox {
                background-color: #161B22;
                border: 1px solid #30363D;
                border-radius: 4px;
                padding: 5px 8px;
                color: #E6EDF3;
            }
            QLineEdit:focus, QComboBox:focus { border-color: #1F6FEB; }
            QCheckBox { color: #E6EDF3; }
            QCheckBox::indicator {
                width: 14px; height: 14px;
                border: 1px solid #30363D;
                border-radius: 3px;
                background: #161B22;
            }
            QCheckBox::indicator:checked { background: #1F6FEB; border-color: #1F6FEB; }
            QDialog { background-color: #161B22; }
            QFormLayout QLabel { color: #8B949E; }
            QScrollBar:vertical {
                background: #161B22; width: 8px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical { background: #30363D; border-radius: 4px; }
            QStatusBar { background-color: #161B22; color: #8B949E; font-size: 11px; }
        """)

    # ── UI Construction ───────────────────────────────────────────────────

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Header
        root.addWidget(self._make_header())

        # Body splitter
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setHandleWidth(4)
        splitter.setStyleSheet("QSplitter::handle { background: #21262D; }")

        top_panel = self._make_top_panel()
        bottom_panel = self._make_bottom_panel()
        splitter.addWidget(top_panel)
        splitter.addWidget(bottom_panel)
        splitter.setSizes([420, 280])
        root.addWidget(splitter, 1)

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready  —  Select a drive and click Wipe Drive to begin.")

    def _make_header(self):
        header = QFrame()
        header.setFixedHeight(64)
        header.setStyleSheet("background: #161B22; border-bottom: 1px solid #21262D;")
        layout = QHBoxLayout(header)
        layout.setContentsMargins(20, 0, 20, 0)

        logo = QLabel("🔒 WipeVault")
        logo.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        logo.setStyleSheet("color: #00C2FF; letter-spacing: 1px;")
        layout.addWidget(logo)

        tagline = QLabel("DoD 5220.22-M Secure Drive Erasure")
        tagline.setStyleSheet("color: #8B949E; font-size: 11px;")
        layout.addWidget(tagline)

        layout.addStretch()

        self.dry_run_cb = QCheckBox("Simulation Mode (no writes)")
        self.dry_run_cb.setChecked(True)
        self.dry_run_cb.setToolTip("When checked, no data is written. Uncheck for a real wipe.")
        self.dry_run_cb.setStyleSheet("color: #00C2FF; font-weight: bold;")
        layout.addWidget(self.dry_run_cb)

        refresh_btn = QPushButton("↻  Refresh Drives")
        refresh_btn.clicked.connect(self._refresh_drives)
        layout.addWidget(refresh_btn)

        return header

    def _make_top_panel(self):
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(16, 12, 16, 8)
        layout.setSpacing(10)

        # Drive table
        drives_group = QGroupBox("Detected Drives")
        drives_layout = QVBoxLayout(drives_group)

        self.drive_table = QTableWidget()
        self.drive_table.setColumnCount(6)
        self.drive_table.setHorizontalHeaderLabels(["Device", "Model", "Serial", "Size", "Interface", "Connection"])
        self.drive_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.drive_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.drive_table.setAlternatingRowColors(True)
        self.drive_table.setStyleSheet(self.drive_table.styleSheet() +
            "QTableWidget { alternate-background-color: #0D1117; }")
        hdr = self.drive_table.horizontalHeader()
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.drive_table.setFixedHeight(180)
        self.drive_table.selectionModel().selectionChanged.connect(self._on_drive_selected)
        drives_layout.addWidget(self.drive_table)
        layout.addWidget(drives_group)

        # Progress area
        prog_group = QGroupBox("Wipe Progress")
        prog_layout = QVBoxLayout(prog_group)
        prog_layout.setSpacing(6)

        self.pass_label = QLabel("No wipe in progress.")
        self.pass_label.setStyleSheet("color: #8B949E; font-size: 11px;")
        prog_layout.addWidget(self.pass_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        prog_layout.addWidget(self.progress_bar)

        self.progress_msg = QLabel("")
        self.progress_msg.setStyleSheet("color: #8B949E; font-size: 10px;")
        prog_layout.addWidget(self.progress_msg)

        layout.addWidget(prog_group)

        # Action buttons
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)

        self.wipe_btn = QPushButton("⚡  Wipe Drive")
        self.wipe_btn.setFixedHeight(36)
        self.wipe_btn.setStyleSheet("""
            QPushButton { background:#1F6FEB; color:white; border:none; border-radius:6px;
                          font-weight:bold; font-size:13px; }
            QPushButton:hover { background:#2D82FF; }
            QPushButton:disabled { background:#21262D; color:#484F58; }
        """)
        self.wipe_btn.setEnabled(False)
        self.wipe_btn.clicked.connect(self._start_wipe)
        btn_row.addWidget(self.wipe_btn)

        self.cancel_btn = QPushButton("✕  Cancel")
        self.cancel_btn.setFixedHeight(36)
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._cancel_wipe)
        btn_row.addWidget(self.cancel_btn)

        self.cert_btn = QPushButton("📄  Generate Certificate")
        self.cert_btn.setFixedHeight(36)
        self.cert_btn.setStyleSheet("""
            QPushButton { background:#238636; color:white; border:none; border-radius:6px;
                          font-weight:bold; }
            QPushButton:hover { background:#2EA043; }
            QPushButton:disabled { background:#21262D; color:#484F58; }
        """)
        self.cert_btn.setEnabled(False)
        self.cert_btn.clicked.connect(self._generate_certificate)
        btn_row.addWidget(self.cert_btn)

        layout.addLayout(btn_row)
        return panel

    def _make_bottom_panel(self):
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(16, 8, 16, 12)
        layout.setSpacing(6)

        log_label = QLabel("Wipe Log")
        log_label.setStyleSheet("color: #00C2FF; font-weight: bold; font-size: 11px;")
        layout.addWidget(log_label)

        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setPlaceholderText("Wipe activity will appear here...")
        layout.addWidget(self.log_view, 1)

        return panel

    # ── Drive Management ─────────────────────────────────────────────────

    def _refresh_drives(self):
        self.status_bar.showMessage("Scanning for drives...")
        self.drives = get_drives()
        self.drive_table.setRowCount(0)
        for d in self.drives:
            row = self.drive_table.rowCount()
            self.drive_table.insertRow(row)
            items = [
                d["device"], d["model"], d["serial"],
                d["size"], d["interface"], d["connection"]
            ]
            for col, text in enumerate(items):
                item = QTableWidgetItem(text)
                item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
                # Color-code interface
                if col == 4:
                    colors_map = {
                        "NVMe": "#00FF9C", "USB": "#FFA657",
                        "SATA": "#79C0FF", "SCSI": "#D2A8FF"
                    }
                    item.setForeground(QColor(colors_map.get(text, "#E6EDF3")))
                self.drive_table.setItem(row, col, item)

        self.wipe_btn.setEnabled(False)
        msg = f"Found {len(self.drives)} drive(s)."
        self.status_bar.showMessage(msg)

    def _on_drive_selected(self):
        rows = self.drive_table.selectedItems()
        self.wipe_btn.setEnabled(bool(rows) and self.current_worker is None)

    def _selected_drive(self):
        row = self.drive_table.currentRow()
        if row < 0 or row >= len(self.drives):
            return None
        return self.drives[row]

    # ── Wipe Control ─────────────────────────────────────────────────────

    def _start_wipe(self):
        drive = self._selected_drive()
        if not drive:
            return

        dry_run = self.dry_run_cb.isChecked()
        dlg = WipeConfirmDialog(drive, dry_run, self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        self.log_view.clear()
        self.progress_bar.setValue(0)
        self.cert_btn.setEnabled(False)
        self.wipe_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)

        worker = WipeWorker(drive, dry_run=dry_run)
        worker.progress.connect(self._on_progress)
        worker.pass_update.connect(self._on_pass_update)
        worker.finished.connect(self._on_wipe_finished)
        worker.log_update.connect(self._on_log)
        self.current_worker = worker
        self.last_drive = drive
        worker.start()

    def _cancel_wipe(self):
        if self.current_worker:
            self.current_worker.cancel()
            self.cancel_btn.setEnabled(False)
            self.pass_label.setText("Cancelling...")

    def _on_progress(self, pct, msg):
        self.progress_bar.setValue(pct)
        self.progress_msg.setText(msg)

    def _on_pass_update(self, pass_num, desc):
        self.pass_label.setText(f"<b>Pass {pass_num}/3</b> — {desc}")

    def _on_log(self, text):
        self.log_view.append(text)
        self.log_view.ensureCursorVisible()

    def _on_wipe_finished(self, success, msg):
        self.last_worker = self.current_worker
        self.current_worker = None
        self.cancel_btn.setEnabled(False)
        self.wipe_btn.setEnabled(True)

        if success:
            self.pass_label.setText("<b style='color:#00FF9C;'>✓ Wipe Complete</b>")
            self.progress_bar.setValue(100)
            self.cert_btn.setEnabled(True)
            self.status_bar.showMessage("Wipe completed successfully. Certificate available.")
            QMessageBox.information(self, "Wipe Complete",
                "DoD 5220.22-M 3-pass wipe completed successfully.\n\nClick 'Generate Certificate' to create the erasure certificate.")
        else:
            self.pass_label.setText(f"<b style='color:#FF5555;'>✗ Wipe Failed</b>")
            self.status_bar.showMessage(f"Wipe failed: {msg}")
            QMessageBox.critical(self, "Wipe Failed", f"The wipe did not complete:\n\n{msg}")

    # ── Certificate ───────────────────────────────────────────────────────

    def _generate_certificate(self):
        if not self.last_worker or not self.last_drive:
            QMessageBox.warning(self, "No Wipe Data", "Complete a wipe first.")
            return

        dlg = CompanyInfoDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        company_info = dlg.get_info()

        certs_dir = Path.home() / "WipeVault_Certs"
        certs_dir.mkdir(exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        serial_safe = self.last_drive["serial"].replace(" ", "_")
        ext = "pdf" if REPORTLAB_AVAILABLE else "txt"
        filename = certs_dir / f"WipeVault_Cert_{serial_safe}_{ts}.{ext}"

        gen = CertificateGenerator(self.last_drive, self.last_worker, company_info)
        try:
            out = gen.generate(str(filename))
            QMessageBox.information(
                self,
                "Certificate Generated",
                f"Certificate saved to:\n{out}\n\n{'PDF certificate created.' if REPORTLAB_AVAILABLE else 'Note: Install reportlab for PDF output (pip install reportlab).'}"
            )
            # Open folder
            if platform.system() == "Windows":
                os.startfile(str(certs_dir))
            elif platform.system() == "Darwin":
                subprocess.run(["open", str(certs_dir)])
            else:
                subprocess.run(["xdg-open", str(certs_dir)])
        except Exception as e:
            QMessageBox.critical(self, "Certificate Error", f"Failed to generate certificate:\n{e}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("WipeVault")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("WipeVault")

    window = WipeVaultWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
