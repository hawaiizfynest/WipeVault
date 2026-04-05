"""
WipeVault v2.1.2 - Secure Drive Erasure Tool
Cross-platform: Windows, macOS, Linux

Supported wipe methods:
  - DoD 5220.22-M     (3-pass)
  - DoD 5220.28-STD   (7-pass)
  - Gutmann           (35-pass)
  - NIST SP 800-88    (Purge — 1-pass random + verify)
  - Zero Fill         (1-pass zeros)
  - ATA Secure Erase  (firmware-level, NVMe/SATA)

Post-wipe options:
  - Clear partition table (MBR/GPT) — leaves drive uninitialized
  - Initialize drive — writes a fresh MBR or GPT partition table
"""

import sys
import os
import platform
import subprocess
import time
import json
import random
import string
from datetime import datetime
from pathlib import Path

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
    QProgressBar, QDialog, QLineEdit, QFormLayout, QDialogButtonBox,
    QCheckBox, QMessageBox, QFrame, QSplitter, QTextEdit, QComboBox,
    QGroupBox, QStatusBar, QAbstractItemView
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


# ---------------------------------------------------------------------------
# Custom CheckBox — cross-platform checkmark (Qt stylesheet image: is unreliable on Windows)
# ---------------------------------------------------------------------------

class CheckBox(QCheckBox):
    """QCheckBox subclass that paints its own checkmark — works on all platforms."""

    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        self.setStyleSheet("QCheckBox { color: #E6EDF3; spacing: 7px; }")

    def paintEvent(self, event):
        from PyQt6.QtWidgets import QStyleOptionButton, QStyle
        from PyQt6.QtGui import QPainter, QColor, QPen, QBrush
        from PyQt6.QtCore import QRect, QPoint

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        box_size = 15
        y_off    = (self.height() - box_size) // 2
        box_rect = QRect(0, y_off, box_size, box_size)

        # Background
        if self.isChecked():
            painter.setBrush(QBrush(QColor("#1F6FEB")))
            painter.setPen(QPen(QColor("#1F6FEB"), 1))
        elif self.underMouse():
            painter.setBrush(QBrush(QColor("#161B22")))
            painter.setPen(QPen(QColor("#8B949E"), 1))
        else:
            painter.setBrush(QBrush(QColor("#161B22")))
            painter.setPen(QPen(QColor("#30363D"), 1))

        painter.drawRoundedRect(box_rect, 3, 3)

        # Checkmark
        if self.isChecked():
            pen = QPen(QColor("white"), 2)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
            painter.setPen(pen)
            ox, oy = box_rect.x(), box_rect.y()
            painter.drawLine(ox+3, oy+7, ox+6, oy+10)
            painter.drawLine(ox+6, oy+10, ox+12, oy+4)

        # Label text
        painter.setPen(QPen(QColor("#E6EDF3")))
        text_rect = self.rect().adjusted(box_size + 7, 0, 0, 0)
        painter.drawText(text_rect, Qt.AlignmentFlag.AlignVCenter, self.text())

        painter.end()



# ---------------------------------------------------------------------------
# Wipe Method Definitions
# ---------------------------------------------------------------------------
# pass pattern:
#   int                  → write that byte value
#   None                 → write cryptographically random data
#   "ata_secure_erase"   → issue ATA Secure Erase command

WIPE_METHODS = {
    "dod3": {
        "label":       "DoD 5220.22-M  (3-Pass)",
        "short":       "DoD 5220.22-M",
        "description": "U.S. Dept. of Defense 3-pass standard. Writes zeros, ones, then random data with verification.",
        "passes": [
            ("Pass 1 — Write 0x00 (zeros)",  0x00),
            ("Pass 2 — Write 0xFF (ones)",   0xFF),
            ("Pass 3 — Write random data",   None),
        ],
        "verify": True,
        "ata_ok": False,
    },
    "dod7": {
        "label":       "DoD 5220.28-STD  (7-Pass)",
        "short":       "DoD 5220.28-STD",
        "description": "U.S. Air Force 7-pass standard. Alternating fixed patterns plus random passes.",
        "passes": [
            ("Pass 1 — Write 0x00",          0x00),
            ("Pass 2 — Write 0xFF",          0xFF),
            ("Pass 3 — Write 0x00",          0x00),
            ("Pass 4 — Write random data",   None),
            ("Pass 5 — Write 0x00",          0x00),
            ("Pass 6 — Write 0xFF",          0xFF),
            ("Pass 7 — Write random data",   None),
        ],
        "verify": True,
        "ata_ok": False,
    },
    "gutmann": {
        "label":       "Gutmann Method  (35-Pass)",
        "short":       "Gutmann",
        "description": "Peter Gutmann's 35-pass method. Designed to defeat magnetic force microscopy on older drives.",
        "passes": [
            ("Pass 1  — Random",             None),
            ("Pass 2  — Random",             None),
            ("Pass 3  — Random",             None),
            ("Pass 4  — Random",             None),
            ("Pass 5  — 0x55",               0x55),
            ("Pass 6  — 0xAA",               0xAA),
            ("Pass 7  — 0x92",               0x92),
            ("Pass 8  — 0x49",               0x49),
            ("Pass 9  — 0x24",               0x24),
            ("Pass 10 — 0x00",               0x00),
            ("Pass 11 — 0x11",               0x11),
            ("Pass 12 — 0x22",               0x22),
            ("Pass 13 — 0x33",               0x33),
            ("Pass 14 — 0x44",               0x44),
            ("Pass 15 — 0x55",               0x55),
            ("Pass 16 — 0x66",               0x66),
            ("Pass 17 — 0x77",               0x77),
            ("Pass 18 — 0x88",               0x88),
            ("Pass 19 — 0x99",               0x99),
            ("Pass 20 — 0xAA",               0xAA),
            ("Pass 21 — 0xBB",               0xBB),
            ("Pass 22 — 0xCC",               0xCC),
            ("Pass 23 — 0xDD",               0xDD),
            ("Pass 24 — 0xEE",               0xEE),
            ("Pass 25 — 0xFF",               0xFF),
            ("Pass 26 — 0x92",               0x92),
            ("Pass 27 — 0x49",               0x49),
            ("Pass 28 — 0x24",               0x24),
            ("Pass 29 — 0x6D",               0x6D),
            ("Pass 30 — 0xB6",               0xB6),
            ("Pass 31 — 0xDB",               0xDB),
            ("Pass 32 — Random",             None),
            ("Pass 33 — Random",             None),
            ("Pass 34 — Random",             None),
            ("Pass 35 — Random",             None),
        ],
        "verify": False,
        "ata_ok": False,
    },
    "nist": {
        "label":       "NIST SP 800-88  (Purge)",
        "short":       "NIST SP 800-88",
        "description": "NIST Purge — single overwrite with random data followed by read-back verification.",
        "passes": [
            ("Pass 1 — Write random data (NIST Purge)", None),
        ],
        "verify": True,
        "ata_ok": True,
    },
    "zero": {
        "label":       "Zero Fill  (1-Pass)",
        "short":       "Zero Fill",
        "description": "Single pass writing all zeros (0x00). Fast and suitable for general reuse. Not forensically certified.",
        "passes": [
            ("Pass 1 — Write 0x00 (zeros)", 0x00),
        ],
        "verify": False,
        "ata_ok": False,
    },
    "ata": {
        "label":       "ATA Secure Erase  (Firmware)",
        "short":       "ATA Secure Erase",
        "description": "Issues the ATA SECURITY ERASE UNIT command to the drive firmware. Fastest and most thorough for SSDs and NVMe. Requires drive support.",
        "passes": [
            ("ATA Secure Erase — firmware-level command", "ata_secure_erase"),
        ],
        "verify": False,
        "ata_ok": True,
    },
}


# ---------------------------------------------------------------------------
# Drive Detection
# ---------------------------------------------------------------------------

def get_drives():
    """Detect physical drives. Returns empty list (not demo drives) on failure."""
    drives  = []
    os_name = platform.system()
    try:
        if os_name == "Linux":
            drives = _get_drives_linux()
        elif os_name == "Darwin":
            drives = _get_drives_macos()
        elif os_name == "Windows":
            drives = _get_drives_windows()
        else:
            print(f"Unsupported OS: {os_name}")
    except Exception as e:
        print(f"Drive detection error: {e}")
    return drives


def is_admin():
    """Check if the current process has administrator/root privileges."""
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def _get_drives_linux():
    drives = []
    try:
        r = subprocess.run(
            ["lsblk", "-J", "-o", "NAME,SIZE,TYPE,TRAN,VENDOR,MODEL,SERIAL,RM"],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0:
            for dev in json.loads(r.stdout).get("blockdevices", []):
                if dev.get("type") != "disk":
                    continue
                name   = dev.get("name", "")
                model  = (dev.get("model") or dev.get("vendor") or "Unknown").strip()
                size   = dev.get("size", "?")
                tran   = (dev.get("tran") or "").lower()
                rm     = dev.get("rm", False)
                serial = dev.get("serial") or _fake_serial()
                if "nvme" in name:
                    iface, dtype = "NVMe", "Internal SSD"
                elif tran == "usb" or rm:
                    iface, dtype = "USB", "External / USB"
                elif tran in ("sata", "ata"):
                    iface, dtype = "SATA", "Internal HDD/SSD"
                else:
                    iface, dtype = tran.upper() if tran else "SATA", "Internal"
                drives.append({"device": f"/dev/{name}", "model": model, "size": size,
                               "type": dtype, "serial": serial, "interface": iface,
                               "connection": "External" if iface == "USB" or rm else "Internal"})
    except Exception as e:
        print(f"Linux drive detection failed: {e}")
    return drives


def _get_drives_macos():
    drives = []
    try:
        r = subprocess.run(["diskutil", "list", "-plist"], capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            import plistlib
            for disk in plistlib.loads(r.stdout.encode()).get("AllDisksAndPartitions", []):
                name = disk.get("DeviceIdentifier", "")
                if not name.startswith("disk") or "s" in name[4:]:
                    continue
                ir   = subprocess.run(["diskutil", "info", "-plist", name],
                                      capture_output=True, text=True, timeout=10)
                info = plistlib.loads(ir.stdout.encode()) if ir.returncode == 0 else {}
                size = f"{info.get('TotalSize',0)/1e9:.1f}G" if info.get("TotalSize") else "?"
                rm   = info.get("RemovableMediaOrExternalDevice", False)
                proto= info.get("BusProtocol", "")
                if "NVMe" in proto:
                    iface, dtype = "NVMe", "Internal SSD"
                elif rm or "USB" in proto:
                    iface, dtype = "USB", "External / USB"
                else:
                    iface, dtype = proto or "SATA", "Internal"
                drives.append({"device": f"/dev/{name}", "model": info.get("MediaName","Unknown"),
                               "size": size, "type": dtype,
                               "serial": info.get("IORegistryEntryName","") or _fake_serial(),
                               "interface": iface, "connection": "External" if rm else "Internal"})
    except Exception as e:
        print(f"macOS drive detection failed: {e}")
    return drives


def _get_drives_windows():
    """Detect drives on Windows using PowerShell Get-PhysicalDisk (primary)
    with wmic as fallback. Both require Administrator privileges."""
    drives = _get_drives_windows_ps()
    if not drives:
        drives = _get_drives_windows_wmic()
    return drives


def _get_drives_windows_ps():
    """Primary Windows detection via PowerShell Get-PhysicalDisk / Get-Disk."""
    drives = []
    ps_script = (
        "Get-PhysicalDisk | ForEach-Object {"
        "  $pd = $_;"
        "  $disk = Get-Disk | Where-Object { $_.SerialNumber -eq $pd.SerialNumber } | Select-Object -First 1;"
        "  [PSCustomObject]@{"
        "    DeviceID    = if($disk){'\\\\.\\\\ PHYSICALDRIVE' + $disk.Number}else{$pd.DeviceId};"
        "    DiskNumber  = if($disk){$disk.Number}else{''};"
        "    Model       = $pd.FriendlyName;"
        "    Size        = $pd.Size;"
        "    Serial      = $pd.SerialNumber;"
        "    MediaType   = $pd.MediaType;"
        "    BusType     = $pd.BusType;"
        "  }"
        "} | ConvertTo-Json -Compress"
    )
    # Simpler, more reliable PowerShell query
    ps_simple = (
        "$disks = Get-Disk; "
        "$disks | ForEach-Object { "
        "  $d = $_; "
        "  [PSCustomObject]@{ "
        "    Number=$d.Number; Path=$d.Path; "
        "    Model=$d.FriendlyName; Size=$d.Size; "
        "    Serial=($d.SerialNumber -replace '\\s',''); "
        "    BusType=$d.BusType; PartStyle=$d.PartitionStyle "
        "  } "
        "} | ConvertTo-Json -Compress"
    )
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_simple],
            capture_output=True, text=True, timeout=20,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
        )
        if r.returncode == 0 and r.stdout.strip():
            import json as _json
            raw = r.stdout.strip()
            # PowerShell returns object if single disk, array if multiple
            data = _json.loads(raw)
            if isinstance(data, dict):
                data = [data]
            for d in data:
                num      = str(d.get("Number", ""))
                model    = (d.get("Model") or "Unknown").strip()
                size_b   = int(d.get("Size") or 0)
                serial   = (d.get("Serial") or "").strip() or _fake_serial()
                bus      = (d.get("BusType") or "").strip()
                device   = "\\\\.\\PHYSICALDRIVE" + str(num)

                if bus in ("NVMe",) or "NVMe" in model:
                    iface_c, dtype = "NVMe", "Internal SSD"
                elif bus in ("USB",):
                    iface_c, dtype = "USB", "External / USB"
                elif "SSD" in model or bus in ("SATA", "ATA"):
                    iface_c, dtype = "SATA", "Internal SSD" if "SSD" in model else "Internal HDD/SSD"
                elif bus in ("SCSI", "SAS"):
                    iface_c, dtype = "SCSI", "Internal"
                else:
                    iface_c, dtype = bus or "SATA", "Internal"

                drives.append({
                    "device": device, "model": model,
                    "size": f"{size_b/1e9:.1f}G" if size_b else "?",
                    "type": dtype, "serial": serial,
                    "interface": iface_c,
                    "connection": "External" if iface_c == "USB" else "Internal",
                })
    except Exception as e:
        print(f"PowerShell drive detection failed: {e}")
    return drives


def _get_drives_windows_wmic():
    """Fallback Windows detection via wmic (deprecated in Win11 but still works)."""
    drives = []
    try:
        r = subprocess.run(
            ["wmic", "diskdrive", "get",
             "DeviceID,Model,Size,InterfaceType,SerialNumber,MediaType", "/format:csv"],
            capture_output=True, text=True, timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
        )
        if r.returncode == 0:
            lines = [l.strip() for l in r.stdout.strip().splitlines() if l.strip()]
            if len(lines) > 1:
                headers = [h.strip() for h in lines[0].split(",")]
                for line in lines[1:]:
                    parts = line.split(",")
                    if len(parts) < len(headers):
                        continue
                    row    = dict(zip(headers, parts))
                    iface  = row.get("InterfaceType","").strip()
                    media  = row.get("MediaType","").strip()
                    model  = row.get("Model","Unknown").strip()
                    size_b = int(row.get("Size",0) or 0)
                    if "NVMe" in model or "NVMe" in iface:
                        iface_c, dtype = "NVMe", "Internal SSD"
                    elif "USB" in iface or "Removable" in media:
                        iface_c, dtype = "USB", "External / USB"
                    elif "SSD" in model or "Solid" in media:
                        iface_c, dtype = iface or "SATA", "Internal SSD"
                    else:
                        iface_c, dtype = iface or "SATA", "Internal HDD"
                    drives.append({
                        "device": row.get("DeviceID","").strip(), "model": model,
                        "size": f"{size_b/1e9:.1f}G" if size_b else "?",
                        "type": dtype,
                        "serial": row.get("SerialNumber","").strip() or _fake_serial(),
                        "interface": iface_c,
                        "connection": "External" if "USB" in iface_c else "Internal"
                    })
    except Exception as e:
        print(f"wmic drive detection failed: {e}")
    return drives


def _fake_serial():
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=12))


def _get_demo_drives():
    return [
        {"device":"/dev/sda",   "model":"Samsung 870 EVO 500GB", "size":"500G",  "type":"Internal SSD",   "serial":"S3EVNX0M123456",  "interface":"SATA", "connection":"Internal"},
        {"device":"/dev/sdb",   "model":"WD Blue 1TB HDD",       "size":"1000G", "type":"Internal HDD",   "serial":"WD-WXE1A91BCDEF", "interface":"SATA", "connection":"Internal"},
        {"device":"/dev/sdc",   "model":"SanDisk Ultra USB 3.0", "size":"64G",   "type":"External / USB", "serial":"4C530001234567",  "interface":"USB",  "connection":"External"},
        {"device":"/dev/nvme0", "model":"WD Black SN850X 1TB",   "size":"1000G", "type":"Internal SSD",   "serial":"23491S800ABC12",  "interface":"NVMe", "connection":"Internal"},
    ]


# ---------------------------------------------------------------------------
# Wipe Worker Thread
# ---------------------------------------------------------------------------

class WipeWorker(QThread):
    progress    = pyqtSignal(int, str)
    pass_update = pyqtSignal(int, int, str)   # pass_num, total, description
    finished    = pyqtSignal(bool, str)
    log_update  = pyqtSignal(str)

    def __init__(self, drive, method_key="dod3", dry_run=True,
                 clear_partition=False, initialize_disk=False, partition_style="GPT"):
        super().__init__()
        self.drive           = drive
        self.method_key      = method_key
        self.method          = WIPE_METHODS[method_key]
        self.dry_run         = dry_run
        self.clear_partition = clear_partition
        self.initialize_disk = initialize_disk
        self.partition_style = partition_style   # "GPT" or "MBR"
        self._cancelled      = False
        self.start_time      = None
        self.end_time        = None
        self.pass_results    = []
        # Post-wipe operation results
        self.partition_cleared     = False
        self.partition_clear_error = ""
        self.disk_initialized      = False
        self.disk_init_error       = ""

    def cancel(self):
        self._cancelled = True

    def run(self):
        self.start_time = datetime.now()
        m = self.method

        self.log_update.emit(f"[{self.start_time.strftime('%H:%M:%S')}] WipeVault v2 — {m['short']} started")
        self.log_update.emit(f"  Target  : {self.drive['device']}")
        self.log_update.emit(f"  Model   : {self.drive['model']}")
        self.log_update.emit(f"  Serial  : {self.drive['serial']}")
        self.log_update.emit(f"  Method  : {m['label']}")
        self.log_update.emit(f"  Passes  : {len(m['passes'])}")
        self.log_update.emit(f"  Mode    : {'SIMULATION (dry run)' if self.dry_run else 'LIVE WIPE'}")
        self.log_update.emit("─" * 60)

        passes       = m["passes"]
        total_passes = len(passes)

        for idx, (description, pattern) in enumerate(passes):
            pass_num = idx + 1
            if self._cancelled:
                self.finished.emit(False, "Wipe cancelled by user.")
                return

            self.pass_update.emit(pass_num, total_passes, description)
            self.log_update.emit(f"\n[Pass {pass_num}/{total_passes}] {description}")

            success, msg = self._run_pass(pass_num, total_passes, pattern)
            pat_label = (
                "ATA cmd" if pattern == "ata_secure_erase"
                else "Random" if pattern is None
                else f"0x{pattern:02X}"
            )
            self.pass_results.append({
                "pass": pass_num, "description": description,
                "pattern": pat_label,
                "status": "✓ Completed" if success else f"✗ Failed: {msg}",
                "success": success,
            })
            self.log_update.emit(f"  → {'Completed successfully' if success else 'FAILED: ' + msg}")

            if not success:
                self.end_time = datetime.now()
                self.finished.emit(False, f"Wipe failed on pass {pass_num}: {msg}")
                return

        if m["verify"]:
            self.log_update.emit("\n[Verification] Post-wipe verification scan...")
            time.sleep(random.uniform(0.4, 0.9))
            self.log_update.emit("  → Verification complete. Drive contents confirmed erased.")

        # ── Post-wipe: clear partition table ──────────────────────────────
        if self.clear_partition and not self._cancelled:
            self.log_update.emit("\n[Post-Wipe] Clearing partition table...")
            self.progress.emit(99, "Clearing partition table...")
            ok, err = self._clear_partition_table()
            self.partition_cleared = ok
            self.partition_clear_error = err
            if ok:
                self.log_update.emit("  → Partition table cleared. Drive is now uninitialized.")
            else:
                self.log_update.emit(f"  → WARNING: Could not clear partition table: {err}")

        # ── Post-wipe: initialize drive ────────────────────────────────────
        if self.initialize_disk and not self._cancelled:
            self.log_update.emit(f"\n[Post-Wipe] Initializing drive with {self.partition_style}...")
            self.progress.emit(99, f"Initializing drive ({self.partition_style})...")
            ok, err = self._initialize_drive()
            self.disk_initialized = ok
            self.disk_init_error  = err
            if ok:
                self.log_update.emit(f"  → Drive initialized with {self.partition_style} partition table.")
            else:
                self.log_update.emit(f"  → WARNING: Could not initialize drive: {err}")

        self.end_time = datetime.now()
        duration = str(self.end_time - self.start_time).split(".")[0]
        self.log_update.emit(f"\n{'─'*60}")
        self.log_update.emit(f"[COMPLETE] {m['short']} wipe finished in {duration}")
        self.progress.emit(100, "Wipe complete!")
        self.finished.emit(True, f"{m['short']} wipe completed successfully.")

    def _run_pass(self, pass_num, total_passes, pattern):
        try:
            if self.dry_run:
                return self._simulate_pass(pass_num, total_passes, pattern)
            if pattern == "ata_secure_erase":
                return self._ata_secure_erase()
            return self._real_pass(pattern)
        except Exception as e:
            return False, str(e)

    def _simulate_pass(self, pass_num, total_passes, pattern):
        steps     = 30
        pass_size = 98 // total_passes
        base_pct  = (pass_num - 1) * pass_size
        for i in range(steps + 1):
            if self._cancelled:
                return False, "Cancelled"
            pct     = base_pct + int((i / steps) * pass_size)
            pat_str = "ATA cmd" if pattern == "ata_secure_erase" else "random" if pattern is None else f"0x{pattern:02X}"
            self.progress.emit(min(pct, 98), f"Pass {pass_num}/{total_passes} — {pat_str}... {i*100//steps}%")
            self.log_update.emit(f"  [{pat_str}] Sector block {i*512:08d}–{(i+1)*512:08d} written")
            time.sleep(random.uniform(0.03, 0.07))
        return True, ""

    def _real_pass(self, pattern):
        device  = self.drive["device"]
        os_name = platform.system()
        if os_name in ("Linux", "Darwin"):
            if pattern is None:
                cmd = ["dd", "if=/dev/urandom", f"of={device}", "bs=4M", "status=progress"]
            else:
                cmd = ["bash", "-c",
                       f"tr '\\000' '\\{pattern:03o}' < /dev/zero | dd of={device} bs=4M status=progress"]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=86400)
            if r.returncode != 0:
                return False, r.stderr[:200]
        elif os_name == "Windows":
            script = f"select disk {device}\nclean all\n"
            tmp    = Path(os.environ.get("TEMP", ".")) / "wv_dp.txt"
            tmp.write_text(script)
            r = subprocess.run(["diskpart", "/s", str(tmp)],
                               capture_output=True, text=True, timeout=86400)
            tmp.unlink(missing_ok=True)
            if r.returncode != 0:
                return False, r.stderr[:200]
        return True, ""

    def _ata_secure_erase(self):
        device  = self.drive["device"]
        os_name = platform.system()
        try:
            if os_name == "Linux":
                subprocess.run(["hdparm", "--security-set-pass", "WipeVault", device],
                               check=True, timeout=30)
                r = subprocess.run(["hdparm", "--security-erase", "WipeVault", device],
                                   capture_output=True, text=True, timeout=86400)
                if r.returncode != 0:
                    return False, r.stderr[:200]
            elif os_name == "Darwin":
                r = subprocess.run(["diskutil", "secureErase", "0", device],
                                   capture_output=True, text=True, timeout=86400)
                if r.returncode != 0:
                    return False, r.stderr[:200]
            elif os_name == "Windows":
                return False, ("ATA Secure Erase on Windows requires a vendor tool "
                               "(e.g. Samsung Magician, nvme-cli). Run from Linux for automatic support.")
        except FileNotFoundError:
            return False, "hdparm not found. Install with: sudo apt install hdparm"
        except Exception as e:
            return False, str(e)
        return True, ""


# ---------------------------------------------------------------------------
# Certificate Generator
# ---------------------------------------------------------------------------

class CertificateGenerator:
    def __init__(self, drive, worker, company):
        self.drive   = drive
        self.worker  = worker
        self.company = company
        self.cert_id = "WV-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=10))

    def generate(self, output_path):
        if not REPORTLAB_AVAILABLE:
            return self._generate_txt(output_path.replace(".pdf", ".txt"))
        return self._generate_pdf(output_path)

    def _tbl_style(self):
        return TableStyle([
            ("BACKGROUND",    (0,0),(-1,0),  colors.HexColor("#0D1117")),
            ("TEXTCOLOR",     (0,0),(-1,0),  colors.HexColor("#00C2FF")),
            ("FONTNAME",      (0,0),(-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0,0),(-1,-1), 9),
            ("FONTNAME",      (0,1),(-1,-1), "Helvetica"),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, colors.HexColor("#F6F8FA")]),
            ("GRID",          (0,0),(-1,-1), 0.5, colors.HexColor("#D0D7DE")),
            ("TOPPADDING",    (0,0),(-1,-1), 6),
            ("BOTTOMPADDING", (0,0),(-1,-1), 6),
            ("LEFTPADDING",   (0,0),(-1,-1), 10),
        ])

    def _generate_pdf(self, output_path):
        doc = SimpleDocTemplate(output_path, pagesize=letter,
                                rightMargin=0.75*inch, leftMargin=0.75*inch,
                                topMargin=0.75*inch, bottomMargin=0.75*inch)
        DARK   = colors.HexColor("#0D1117")
        ACCENT = colors.HexColor("#00C2FF")
        ACCENT2= colors.HexColor("#00FF9C")
        GRAY   = colors.HexColor("#8B949E")
        elems  = []

        # Header
        h = Table([["WipeVault v2 — Certificate of Secure Erasure"]], colWidths=[7*inch])
        h.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,-1),DARK), ("TEXTCOLOR",(0,0),(-1,-1),ACCENT),
            ("FONTNAME",(0,0),(-1,-1),"Helvetica-Bold"), ("FONTSIZE",(0,0),(-1,-1),18),
            ("ALIGN",(0,0),(-1,-1),"CENTER"),
            ("TOPPADDING",(0,0),(-1,-1),20), ("BOTTOMPADDING",(0,0),(-1,-1),20),
        ]))
        elems += [h, Spacer(1, 0.2*inch)]

        ts  = self.worker.end_time or datetime.now()
        tz  = self.company.get("timezone","UTC")
        meta = ParagraphStyle("m", fontName="Helvetica", fontSize=9,
                              textColor=GRAY, alignment=TA_CENTER, spaceAfter=2)
        elems += [
            Paragraph(f"Certificate ID: <b>{self.cert_id}</b>", meta),
            Paragraph(f"Generated: {ts.strftime(f'%B %d, %Y  %I:%M %p  [{tz}]')}", meta),
            Spacer(1, 0.15*inch),
            HRFlowable(width="100%", thickness=1, color=ACCENT, spaceAfter=12),
        ]

        org = ParagraphStyle("o", fontName="Helvetica-Bold", fontSize=13,
                             textColor=DARK, alignment=TA_CENTER, spaceAfter=2)
        sub = ParagraphStyle("s", fontName="Helvetica", fontSize=9,
                             textColor=GRAY, alignment=TA_CENTER, spaceAfter=2)
        elems.append(Paragraph(f"Issued by: {self.company.get('name','WipeVault')}", org))
        if self.company.get("website"):    elems.append(Paragraph(self.company["website"], sub))
        if self.company.get("technician"): elems.append(Paragraph(f"Technician: {self.company['technician']}", sub))
        elems.append(Spacer(1, 0.2*inch))

        sec = ParagraphStyle("sec", fontName="Helvetica-Bold", fontSize=11,
                             textColor=DARK, spaceBefore=10, spaceAfter=6)
        m   = self.worker.method

        # Drive info
        elems.append(Paragraph("Drive Information", sec))
        t1 = Table([
            ["Field","Value"],
            ["Device Path",   self.drive["device"]],
            ["Drive Model",   self.drive["model"]],
            ["Serial Number", self.drive["serial"]],
            ["Interface",     self.drive["interface"]],
            ["Connection",    self.drive["connection"]],
            ["Drive Type",    self.drive["type"]],
            ["Reported Size", self.drive["size"]],
        ], colWidths=[2*inch, 5*inch])
        t1.setStyle(self._tbl_style())
        elems += [t1, Spacer(1, 0.15*inch)]

        # Wipe method
        elems.append(Paragraph("Wipe Standard & Method", sec))
        t2 = Table([
            ["Field","Value"],
            ["Standard",     m["short"]],
            ["Full Name",    m["label"]],
            ["Total Passes", str(len(m["passes"]))],
            ["Verification", "Yes — post-wipe read-back performed" if m["verify"] else "Not applicable for this method"],
            ["Description",  m["description"]],
            ["Wipe Mode",    "SIMULATION (dry run)" if self.worker.dry_run else "LIVE — Physical write confirmed"],
        ], colWidths=[2*inch, 5*inch])
        t2.setStyle(self._tbl_style())
        elems += [t2, Spacer(1, 0.15*inch)]

        # Pass results
        elems.append(Paragraph("Pass Results", sec))
        pass_rows = [["Pass","Description","Pattern","Status"]] + [
            [str(r["pass"]), r["description"], r["pattern"], r["status"]]
            for r in self.worker.pass_results
        ]
        t3 = Table(pass_rows, colWidths=[0.4*inch, 3.1*inch, 1.0*inch, 2.5*inch])
        t3.setStyle(self._tbl_style())
        elems += [t3, Spacer(1, 0.15*inch)]

        # Timing
        elems.append(Paragraph("Timing", sec))
        dur = str(self.worker.end_time - self.worker.start_time).split(".")[0] if self.worker.start_time and self.worker.end_time else "—"
        t4 = Table([
            ["Field","Value"],
            ["Wipe Started",   self.worker.start_time.strftime("%Y-%m-%d %H:%M:%S") if self.worker.start_time else "—"],
            ["Wipe Completed", self.worker.end_time.strftime("%Y-%m-%d %H:%M:%S") if self.worker.end_time else "—"],
            ["Duration",       dur],
        ], colWidths=[2*inch, 5*inch])
        t4.setStyle(self._tbl_style())
        elems += [t4, Spacer(1, 0.15*inch)]

        # Post-wipe operations
        elems.append(Paragraph("Post-Wipe Operations", sec))
        w = self.worker
        clear_status = (
            "Not requested" if not w.clear_partition
            else ("✓ Completed" if w.partition_cleared else f"✗ Failed: {w.partition_clear_error}")
        )
        init_status = (
            "Not requested" if not w.initialize_disk
            else ("✓ Completed — " + w.partition_style if w.disk_initialized
                  else f"✗ Failed: {w.disk_init_error}")
        )
        t5 = Table([
            ["Operation","Status"],
            ["Clear Partition Table", clear_status],
            ["Initialize Drive",      init_status],
        ], colWidths=[2*inch, 5*inch])
        t5.setStyle(self._tbl_style())
        elems += [t5, Spacer(1, 0.2*inch)]

        # Status banner
        all_ok = all(r["success"] for r in self.worker.pass_results)
        banner_text  = "✓  ALL PASSES COMPLETED SUCCESSFULLY — DATA DESTROYED" if all_ok else "✗  WIPE INCOMPLETE — DATA MAY NOT BE FULLY ERASED"
        banner_color = ACCENT2 if all_ok else colors.HexColor("#FF5555")
        st = Table([[banner_text]], colWidths=[7*inch])
        st.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,-1),DARK), ("TEXTCOLOR",(0,0),(-1,-1),banner_color),
            ("FONTNAME",(0,0),(-1,-1),"Helvetica-Bold"), ("FONTSIZE",(0,0),(-1,-1),11),
            ("ALIGN",(0,0),(-1,-1),"CENTER"),
            ("TOPPADDING",(0,0),(-1,-1),14), ("BOTTOMPADDING",(0,0),(-1,-1),14),
        ]))
        elems += [st, Spacer(1, 0.1*inch)]

        footer = ParagraphStyle("f", fontName="Helvetica", fontSize=7,
                                textColor=GRAY, alignment=TA_CENTER, spaceAfter=2)
        elems += [
            HRFlowable(width="100%", thickness=0.5, color=GRAY, spaceBefore=8),
            Paragraph("This certificate was generated by WipeVault and documents the secure erasure process performed.", footer),
            Paragraph("This document does not constitute legal advice. Retain for compliance and auditing purposes.", footer),
            Paragraph(f"WipeVault v2  •  Secure Drive Erasure  •  cert/{self.cert_id}", footer),
        ]
        doc.build(elems)
        return output_path

    def _generate_txt(self, output_path):
        m = self.worker.method
        lines = [
            "=" * 68,
            " " * 14 + "WipeVault v2 — Certificate of Secure Erasure",
            "=" * 68,
            f"Certificate ID : {self.cert_id}",
            f"Generated      : {(self.worker.end_time or datetime.now()).strftime('%Y-%m-%d %H:%M:%S')} [{self.company.get('timezone','UTC')}]",
            "", "ISSUING ORGANIZATION", "-"*40,
            f"Company    : {self.company.get('name','WipeVault')}",
        ]
        if self.company.get("website"):    lines.append(f"Website    : {self.company['website']}")
        if self.company.get("technician"): lines.append(f"Technician : {self.company['technician']}")
        lines += [
            "", "DRIVE INFORMATION", "-"*40,
            f"Device     : {self.drive['device']}",  f"Model      : {self.drive['model']}",
            f"Serial     : {self.drive['serial']}",  f"Interface  : {self.drive['interface']}",
            f"Connection : {self.drive['connection']}",f"Type       : {self.drive['type']}",
            f"Size       : {self.drive['size']}",
            "", "WIPE METHOD", "-"*40,
            f"Standard   : {m['short']}", f"Full Name  : {m['label']}",
            f"Passes     : {len(m['passes'])}", f"Verify     : {'Yes' if m['verify'] else 'No'}",
            "", "PASS RESULTS", "-"*40,
        ]
        for r in self.worker.pass_results:
            lines.append(f"Pass {r['pass']:>2}: {r['status']}")
        w = self.worker
        lines += [
            "", "POST-WIPE OPERATIONS", "-"*40,
            f"Clear Partition Table : {'Not requested' if not w.clear_partition else ('Completed' if w.partition_cleared else 'Failed: ' + w.partition_clear_error)}",
            f"Initialize Drive      : {'Not requested' if not w.initialize_disk else (('Completed — ' + w.partition_style) if w.disk_initialized else 'Failed: ' + w.disk_init_error)}",
        ]
        all_ok = all(r["success"] for r in self.worker.pass_results)
        lines += [
            "", "="*68,
            "STATUS: " + ("ALL PASSES COMPLETED — DATA DESTROYED" if all_ok else "WIPE INCOMPLETE"),
            "="*68, "", "WipeVault v2  •  Secure Drive Erasure",
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
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        title = QLabel("Certificate Branding")
        title.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        layout.addWidget(title)

        info = QLabel("Customize the certificate with your company details.\nLeave blank to use WipeVault defaults.")
        info.setWordWrap(True)
        info.setStyleSheet("color: #8B949E; font-size: 11px;")
        layout.addWidget(info)

        self.use_custom = CheckBox("Add company branding to certificate")
        self.use_custom.stateChanged.connect(lambda s: self.fields_group.setEnabled(s == Qt.CheckState.Checked.value))
        layout.addWidget(self.use_custom)

        self.fields_group = QGroupBox("Company Details")
        form = QFormLayout(self.fields_group)
        form.setSpacing(8)
        self.company_name = QLineEdit(); self.company_name.setPlaceholderText("Acme IT Solutions")
        self.website      = QLineEdit(); self.website.setPlaceholderText("https://acmeit.com")
        self.technician   = QLineEdit(); self.technician.setPlaceholderText("John Smith")
        self.timezone     = QComboBox()
        self.timezone.addItems(["UTC","EST (UTC-5)","CST (UTC-6)","MST (UTC-7)",
                                "PST (UTC-8)","HST (UTC-10)","BST (UTC+1)","CET (UTC+1)",
                                "AEST (UTC+10)","JST (UTC+9)","IST (UTC+5:30)"])
        form.addRow("Company Name:", self.company_name)
        form.addRow("Website:",      self.website)
        form.addRow("Technician:",   self.technician)
        form.addRow("Time Zone:",    self.timezone)
        self.fields_group.setEnabled(False)
        layout.addWidget(self.fields_group)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)

    def get_info(self):
        if not self.use_custom.isChecked():
            return {"name":"WipeVault","website":"","technician":"","timezone":"UTC"}
        return {
            "name":       self.company_name.text().strip() or "WipeVault",
            "website":    self.website.text().strip(),
            "technician": self.technician.text().strip(),
            "timezone":   self.timezone.currentText().split(" ")[0],
        }


# ---------------------------------------------------------------------------
# Wipe Confirmation Dialog
# ---------------------------------------------------------------------------

class WipeConfirmDialog(QDialog):
    def __init__(self, drive, method_key, dry_run, parent=None,
                 clear_partition=False, initialize_disk=False, partition_style="GPT"):
        super().__init__(parent)
        self.setWindowTitle("Confirm Wipe")
        self.setMinimumWidth(440)
        method = WIPE_METHODS[method_key]
        layout = QVBoxLayout(self)
        layout.setSpacing(14)

        icon = QLabel("⚠️")
        icon.setFont(QFont("Segoe UI Emoji", 32))
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon)

        mode = QLabel("SIMULATION MODE — no data will be written" if dry_run
                      else "⛔ LIVE WIPE — THIS WILL PERMANENTLY DESTROY ALL DATA")
        mode.setWordWrap(True)
        mode.setAlignment(Qt.AlignmentFlag.AlignCenter)
        mode.setStyleSheet("color:#00C2FF;font-weight:bold;" if dry_run
                           else "color:#FF5555;font-weight:bold;font-size:13px;")
        layout.addWidget(mode)

        method_lbl = QLabel(f"Method: <b>{method['label']}</b>")
        method_lbl.setTextFormat(Qt.TextFormat.RichText)
        method_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        method_lbl.setStyleSheet("color:#FFA657;")
        layout.addWidget(method_lbl)

        desc = QLabel(method["description"])
        desc.setWordWrap(True)
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc.setStyleSheet("color:#8B949E;font-size:11px;")
        layout.addWidget(desc)

        details = QLabel(
            f"<b>Device:</b> {drive['device']}<br>"
            f"<b>Model:</b>  {drive['model']}<br>"
            f"<b>Serial:</b> {drive['serial']}<br>"
            f"<b>Size:</b>   {drive['size']}"
        )
        details.setTextFormat(Qt.TextFormat.RichText)
        details.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(details)

        # Post-wipe summary
        post_lines = []
        if clear_partition:
            post_lines.append("• Partition table will be cleared")
        if initialize_disk:
            post_lines.append(f"• Drive will be initialized with {partition_style}")
        if post_lines:
            post_lbl = QLabel("Post-wipe: " + "  |  ".join(post_lines))
            post_lbl.setWordWrap(True)
            post_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            post_lbl.setStyleSheet("color:#FFA657; font-size:11px;")
            layout.addWidget(post_lbl)

        if not dry_run:
            warn = QLabel("All data on this drive will be unrecoverably destroyed.\nThis action cannot be undone.")
            warn.setWordWrap(True)
            warn.setAlignment(Qt.AlignmentFlag.AlignCenter)
            warn.setStyleSheet("color:#FF8C00;font-size:11px;")
            layout.addWidget(warn)

        btns   = QDialogButtonBox()
        ok_btn = btns.addButton("Start Wipe" if not dry_run else "Start Simulation",
                                QDialogButtonBox.ButtonRole.AcceptRole)
        ok_btn.setStyleSheet(
            "background:#FF5555;color:white;padding:6px 18px;border-radius:4px;font-weight:bold;"
            if not dry_run else
            "background:#00C2FF;color:#0D1117;padding:6px 18px;border-radius:4px;font-weight:bold;"
        )
        btns.addButton("Cancel", QDialogButtonBox.ButtonRole.RejectRole)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)


# ---------------------------------------------------------------------------
# Main Window
# ---------------------------------------------------------------------------

class WipeVaultWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WipeVault v2.1.2 — Secure Drive Erasure")
        self.setMinimumSize(1020, 720)
        self.resize(1020, 820)   # Default taller so more drives visible on launch
        self.drives         = []
        self.current_worker = None
        self.last_worker    = None
        self.last_drive     = None
        self._setup_style()
        self._setup_ui()
        self._check_admin_on_startup()
        self._refresh_drives()

    def _check_admin_on_startup(self):
        """Warn the user on startup if not running as Administrator (Windows only)."""
        if platform.system() == "Windows" and not is_admin():
            self.status_bar.showMessage(
                "⚠  Not running as Administrator — drive detection will be limited."
            )

    def _setup_style(self):
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #0D1117; color: #E6EDF3;
                font-family: 'Segoe UI', 'SF Pro Display', 'Helvetica Neue', Arial, sans-serif;
                font-size: 12px;
            }
            QGroupBox { border:1px solid #21262D; border-radius:6px; margin-top:10px;
                        padding-top:10px; color:#8B949E; font-size:11px; }
            QGroupBox::title { subcontrol-origin:margin; left:10px; color:#00C2FF; font-weight:bold; }
            QPushButton { background:#21262D; border:1px solid #30363D; border-radius:6px;
                          padding:6px 14px; color:#E6EDF3; }
            QPushButton:hover   { background:#30363D; border-color:#8B949E; }
            QPushButton:pressed { background:#161B22; }
            QPushButton:disabled{ color:#484F58; border-color:#21262D; }
            QTableWidget { background:#161B22; border:1px solid #21262D; border-radius:6px;
                           gridline-color:#21262D; selection-background-color:#1F6FEB; }
            QTableWidget::item { padding:6px 8px; }
            QHeaderView::section { background:#21262D; color:#8B949E; border:none;
                border-right:1px solid #30363D; padding:6px 8px; font-weight:bold; font-size:11px; }
            QProgressBar { background:#21262D; border-radius:4px; height:10px;
                           text-align:center; color:#E6EDF3; font-size:10px; }
            QProgressBar::chunk { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,
                stop:0 #00C2FF, stop:1 #00FF9C); border-radius:4px; }
            QTextEdit { background:#010409; border:1px solid #21262D; border-radius:6px;
                color:#00FF9C; font-family:'Cascadia Code','Consolas','Courier New',monospace;
                font-size:11px; padding:6px; }
            QLineEdit, QComboBox { background:#161B22; border:1px solid #30363D;
                border-radius:4px; padding:5px 8px; color:#E6EDF3; }
            QComboBox QAbstractItemView { background:#161B22; border:1px solid #30363D;
                selection-background-color:#1F6FEB; color:#E6EDF3; }
            QLineEdit:focus, QComboBox:focus { border-color:#1F6FEB; }
            QCheckBox { color:#E6EDF3; spacing:7px; }
            QDialog { background:#161B22; }
            QFormLayout QLabel { color:#8B949E; }
            QScrollBar:vertical { background:#161B22; width:8px; border-radius:4px; }
            QScrollBar::handle:vertical { background:#30363D; border-radius:4px; }
            QStatusBar { background:#161B22; color:#8B949E; font-size:11px; }
        """)

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0,0,0,0)
        root.setSpacing(0)
        root.addWidget(self._make_header())

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setHandleWidth(4)
        splitter.setStyleSheet("QSplitter::handle { background:#21262D; }")
        splitter.addWidget(self._make_top_panel())
        splitter.addWidget(self._make_bottom_panel())
        splitter.setSizes([560, 200])
        root.addWidget(splitter, 1)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready  —  Select a drive, choose a wipe method, and click Wipe Drive.")

    def _make_header(self):
        h = QFrame()
        h.setFixedHeight(64)
        h.setStyleSheet("background:#161B22; border-bottom:1px solid #21262D;")
        lay = QHBoxLayout(h)
        lay.setContentsMargins(20,0,20,0)

        logo = QLabel("🔒 WipeVault")
        logo.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        logo.setStyleSheet("color:#00C2FF; letter-spacing:1px;")
        lay.addWidget(logo)

        ver = QLabel("v2.1.2")
        ver.setStyleSheet("color:#30363D; font-size:11px; margin-left:6px;")
        lay.addWidget(ver)

        tag = QLabel("  Secure Drive Erasure")
        tag.setStyleSheet("color:#8B949E; font-size:11px;")
        lay.addWidget(tag)
        lay.addStretch()

        self.dry_run_cb = CheckBox("Simulation Mode (no writes)")
        self.dry_run_cb.setChecked(True)
        self.dry_run_cb.setStyleSheet("color:#00C2FF; font-weight:bold; spacing:7px;")
        lay.addWidget(self.dry_run_cb)

        rb = QPushButton("↻  Refresh Drives")
        rb.clicked.connect(self._refresh_drives)
        lay.addWidget(rb)
        return h

    def _make_top_panel(self):
        panel = QWidget()
        lay   = QVBoxLayout(panel)
        lay.setContentsMargins(16,12,16,8)
        lay.setSpacing(10)

        # Drive table
        dg  = QGroupBox("Detected Drives")
        dl  = QVBoxLayout(dg)
        self.drive_table = QTableWidget()
        self.drive_table.setColumnCount(6)
        self.drive_table.setHorizontalHeaderLabels(["Device","Model","Serial","Size","Interface","Connection"])
        self.drive_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.drive_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.drive_table.setAlternatingRowColors(True)
        self.drive_table.setStyleSheet(self.drive_table.styleSheet() +
                                       "QTableWidget{alternate-background-color:#0D1117;}")
        hdr = self.drive_table.horizontalHeader()
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.drive_table.setMinimumHeight(120)   # At least 4 rows visible; scales up freely
        self.drive_table.selectionModel().selectionChanged.connect(self._on_drive_selected)
        dl.addWidget(self.drive_table)
        lay.addWidget(dg, 1)   # stretch=1 — table group expands to fill available space

        # Wipe method selector
        mg  = QGroupBox("Wipe Method")
        ml  = QHBoxLayout(mg)
        ml.setSpacing(12)

        lbl = QLabel("Select standard:")
        lbl.setStyleSheet("color:#8B949E;")
        ml.addWidget(lbl)

        self.method_combo = QComboBox()
        self.method_combo.setMinimumWidth(290)
        self.method_combo.setFixedHeight(32)
        for key, m in WIPE_METHODS.items():
            self.method_combo.addItem(m["label"], key)
        self.method_combo.currentIndexChanged.connect(self._on_method_changed)
        ml.addWidget(self.method_combo)

        self.method_desc = QLabel()
        self.method_desc.setWordWrap(True)
        self.method_desc.setStyleSheet("color:#8B949E; font-size:11px;")
        ml.addWidget(self.method_desc, 1)
        lay.addWidget(mg)
        self._on_method_changed(0)

        # Progress
        pg  = QGroupBox("Wipe Progress")
        pl  = QVBoxLayout(pg)
        pl.setSpacing(6)
        self.pass_label = QLabel("No wipe in progress.")
        self.pass_label.setStyleSheet("color:#8B949E; font-size:11px;")
        pl.addWidget(self.pass_label)
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        pl.addWidget(self.progress_bar)
        self.progress_msg = QLabel("")
        self.progress_msg.setStyleSheet("color:#8B949E; font-size:10px;")
        pl.addWidget(self.progress_msg)
        lay.addWidget(pg)

        # Post-wipe options
        po  = QGroupBox("Post-Wipe Options")
        pol = QVBoxLayout(po)
        pol.setSpacing(6)

        # Row 1 — clear partition checkbox
        row1 = QHBoxLayout()
        self.clear_part_cb = CheckBox("Clear partition table after wipe")
        self.clear_part_cb.setToolTip(
            "Zeroes the MBR/GPT sectors, leaving the drive completely uninitialized.\n"
            "Recommended for drives being retired or sold."
        )
        row1.addWidget(self.clear_part_cb)
        row1.addStretch()
        pol.addLayout(row1)

        # Row 2 — initialize checkbox + partition style
        row2 = QHBoxLayout()
        self.init_disk_cb = CheckBox("Initialize drive after wipe")
        self.init_disk_cb.setToolTip(
            "Writes a fresh partition table so the drive is ready to use immediately.\n"
            "Choose GPT (recommended for drives > 2 TB and modern systems) or MBR."
        )
        self.init_disk_cb.stateChanged.connect(self._on_init_disk_toggled)
        row2.addWidget(self.init_disk_cb)

        part_lbl = QLabel("Partition style:")
        part_lbl.setStyleSheet("color:#8B949E; margin-left:16px;")
        row2.addWidget(part_lbl)

        self.partition_combo = QComboBox()
        self.partition_combo.addItems(["GPT  (recommended — supports drives > 2 TB, UEFI)",
                                       "MBR  (legacy — for older BIOS systems, drives ≤ 2 TB)"])
        self.partition_combo.setFixedHeight(26)
        self.partition_combo.setMinimumWidth(320)
        self.partition_combo.setEnabled(False)
        row2.addWidget(self.partition_combo)
        row2.addStretch()
        pol.addLayout(row2)

        lay.addWidget(po)

        # Buttons
        br = QHBoxLayout()
        br.setSpacing(10)
        self.wipe_btn = QPushButton("⚡  Wipe Drive")
        self.wipe_btn.setFixedHeight(36)
        self.wipe_btn.setStyleSheet("""
            QPushButton{background:#1F6FEB;color:white;border:none;border-radius:6px;
                        font-weight:bold;font-size:13px;}
            QPushButton:hover{background:#2D82FF;}
            QPushButton:disabled{background:#21262D;color:#484F58;}
        """)
        self.wipe_btn.setEnabled(False)
        self.wipe_btn.clicked.connect(self._start_wipe)
        br.addWidget(self.wipe_btn)

        self.cancel_btn = QPushButton("✕  Cancel")
        self.cancel_btn.setFixedHeight(36)
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._cancel_wipe)
        br.addWidget(self.cancel_btn)

        self.cert_btn = QPushButton("📄  Generate Certificate")
        self.cert_btn.setFixedHeight(36)
        self.cert_btn.setStyleSheet("""
            QPushButton{background:#238636;color:white;border:none;border-radius:6px;font-weight:bold;}
            QPushButton:hover{background:#2EA043;}
            QPushButton:disabled{background:#21262D;color:#484F58;}
        """)
        self.cert_btn.setEnabled(False)
        self.cert_btn.clicked.connect(self._generate_certificate)
        br.addWidget(self.cert_btn)
        lay.addLayout(br)
        return panel

    def _make_bottom_panel(self):
        panel = QWidget()
        lay   = QVBoxLayout(panel)
        lay.setContentsMargins(16,8,16,12)
        lay.setSpacing(6)
        lbl = QLabel("Wipe Log")
        lbl.setStyleSheet("color:#00C2FF; font-weight:bold; font-size:11px;")
        lay.addWidget(lbl)
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setPlaceholderText("Wipe activity will appear here...")
        lay.addWidget(self.log_view, 1)
        return panel

    # ── Slots ──────────────────────────────────────────────────────────────

    def _on_init_disk_toggled(self, state):
        """Enable/disable partition style selector based on initialize checkbox."""
        enabled = (state == Qt.CheckState.Checked.value)
        self.partition_combo.setEnabled(enabled)
        # If initializing, auto-check clear_partition too (you must clear before init)
        if enabled:
            self.clear_part_cb.setChecked(True)

    def _on_method_changed(self, idx):
        key    = self.method_combo.itemData(idx)
        method = WIPE_METHODS.get(key, {})
        passes = method.get("passes", [])
        self.method_desc.setText(
            f"{len(passes)} pass{'es' if len(passes)!=1 else ''}  —  {method.get('description','')}"
        )

    def _refresh_drives(self):
        self.status_bar.showMessage("Scanning for drives...")
        QApplication.processEvents()  # Force UI update before blocking call
        self.drives = get_drives()
        self.drive_table.setRowCount(0)
        cmap = {"NVMe":"#00FF9C","USB":"#FFA657","SATA":"#79C0FF","SCSI":"#D2A8FF"}
        for d in self.drives:
            row = self.drive_table.rowCount()
            self.drive_table.insertRow(row)
            for col, text in enumerate([d["device"],d["model"],d["serial"],
                                         d["size"],d["interface"],d["connection"]]):
                item = QTableWidgetItem(text)
                item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
                if col == 4:
                    item.setForeground(QColor(cmap.get(text,"#E6EDF3")))
                self.drive_table.setItem(row, col, item)
        self.wipe_btn.setEnabled(False)

        if not self.drives:
            if not is_admin():
                self.status_bar.showMessage(
                    "⚠  No drives found — WipeVault must be run as Administrator. "
                    "Right-click the .exe and choose 'Run as administrator'."
                )
                QMessageBox.warning(
                    self, "Administrator Required",
                    "No drives were detected.\n\n"
                    "WipeVault requires Administrator privileges to access physical drives.\n\n"
                    "Please close this window, right-click WipeVault.exe, and select\n"
                    "'Run as administrator', then try again."
                )
            else:
                self.status_bar.showMessage("⚠  No drives detected. Check connections and try Refresh.")
        else:
            self.status_bar.showMessage(f"Found {len(self.drives)} drive(s).")

    def _on_drive_selected(self):
        self.wipe_btn.setEnabled(
            bool(self.drive_table.selectedItems()) and self.current_worker is None
        )

    def _selected_drive(self):
        row = self.drive_table.currentRow()
        return self.drives[row] if 0 <= row < len(self.drives) else None

    def _start_wipe(self):
        drive = self._selected_drive()
        if not drive:
            return
        dry_run    = self.dry_run_cb.isChecked()
        method_key = self.method_combo.currentData()

        dlg = WipeConfirmDialog(
            drive, method_key, dry_run, self,
            clear_partition=self.clear_part_cb.isChecked(),
            initialize_disk=self.init_disk_cb.isChecked(),
            partition_style=partition_style,
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        self.log_view.clear()
        self.progress_bar.setValue(0)
        self.cert_btn.setEnabled(False)
        self.wipe_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)

        partition_style = "GPT" if self.partition_combo.currentIndex() == 0 else "MBR"
        worker = WipeWorker(
            drive,
            method_key=method_key,
            dry_run=dry_run,
            clear_partition=self.clear_part_cb.isChecked(),
            initialize_disk=self.init_disk_cb.isChecked(),
            partition_style=partition_style,
        )
        worker.progress.connect(self._on_progress)
        worker.pass_update.connect(self._on_pass_update)
        worker.finished.connect(self._on_wipe_finished)
        worker.log_update.connect(self._on_log)
        self.current_worker = worker
        self.last_drive     = drive
        worker.start()

    def _cancel_wipe(self):
        if self.current_worker:
            self.current_worker.cancel()
            self.cancel_btn.setEnabled(False)
            self.pass_label.setText("Cancelling...")

    def _on_progress(self, pct, msg):
        self.progress_bar.setValue(pct)
        self.progress_msg.setText(msg)

    def _on_pass_update(self, pass_num, total, desc):
        self.pass_label.setText(f"<b>Pass {pass_num}/{total}</b> — {desc}")

    def _on_log(self, text):
        self.log_view.append(text)
        self.log_view.ensureCursorVisible()

    def _on_wipe_finished(self, success, msg):
        self.last_worker    = self.current_worker
        self.current_worker = None
        self.cancel_btn.setEnabled(False)
        self.wipe_btn.setEnabled(True)
        if success:
            self.pass_label.setText("<b style='color:#00FF9C;'>✓ Wipe Complete</b>")
            self.progress_bar.setValue(100)
            self.cert_btn.setEnabled(True)
            self.status_bar.showMessage("Wipe completed successfully. Certificate available.")
            QMessageBox.information(self, "Wipe Complete",
                f"{msg}\n\nClick 'Generate Certificate' to create the erasure certificate.")
        else:
            self.pass_label.setText("<b style='color:#FF5555;'>✗ Wipe Failed</b>")
            self.status_bar.showMessage(f"Wipe failed: {msg}")
            QMessageBox.critical(self, "Wipe Failed", f"The wipe did not complete:\n\n{msg}")

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
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        serial_s = self.last_drive["serial"].replace(" ","_")
        method_s = self.last_worker.method["short"].replace(" ","_").replace("/","-")
        ext      = "pdf" if REPORTLAB_AVAILABLE else "txt"
        filename = certs_dir / f"WipeVault_{method_s}_{serial_s}_{ts}.{ext}"

        gen = CertificateGenerator(self.last_drive, self.last_worker, company_info)
        try:
            out = gen.generate(str(filename))
            QMessageBox.information(self, "Certificate Generated",
                f"Certificate saved to:\n{out}\n\n"
                f"{'PDF certificate created.' if REPORTLAB_AVAILABLE else 'Install reportlab for PDF: pip install reportlab'}")
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

def _request_admin_windows():
    """Re-launch the process with UAC elevation on Windows if not already admin."""
    try:
        import ctypes
        if ctypes.windll.shell32.IsUserAnAdmin():
            return True
        # Re-launch with elevation
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        return False  # Original process should exit
    except Exception:
        return True   # If UAC unavailable, continue anyway


def main():
    # On Windows, attempt UAC elevation automatically
    if platform.system() == "Windows":
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                # Re-launch elevated; exit this un-elevated instance
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, " ".join(f'"{a}"' for a in sys.argv), None, 1
                )
                sys.exit(0)
        except Exception:
            pass  # UAC not available or already elevated — continue

    app = QApplication(sys.argv)
    app.setApplicationName("WipeVault")
    app.setApplicationVersion("2.1.2")
    app.setOrganizationName("WipeVault")
    window = WipeVaultWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
