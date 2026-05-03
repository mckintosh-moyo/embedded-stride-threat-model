# STRIDE Threat Model Report Generator
# Author: Mckintosh Mpumelelo Moyo — MS Cybersecurity, Yeshiva University
# Description: Generates a color-coded HTML threat report from
#              the STRIDE analysis of an embedded IoT device

import datetime

# ── Threat data ───────────────────────────────────────────────────────────────
threats = [
    # Bootloader
    {"id": "ST-001", "component": "Bootloader", "stride": "Tampering",
     "threat": "Bootloader modified to load unsigned firmware",
     "scenario": "Attacker with physical access replaces bootloader with malicious version",
     "nist": "PR.PS-05", "risk": "CRITICAL"},
    {"id": "ST-002", "component": "Bootloader", "stride": "Elevation of Privilege",
     "threat": "Bootloader bypass grants root access",
     "scenario": "Attacker exploits bootloader vulnerability to gain unrestricted root shell",
     "nist": "PR.AA-05", "risk": "CRITICAL"},
    {"id": "ST-003", "component": "Bootloader", "stride": "Information Disclosure",
     "threat": "Bootloader exposes encryption keys in memory",
     "scenario": "Attacker uses JTAG to dump bootloader memory and extract device keys",
     "nist": "PR.DS-01", "risk": "HIGH"},
    {"id": "ST-004", "component": "Bootloader", "stride": "Repudiation",
     "threat": "No logging of bootloader events",
     "scenario": "Malicious firmware loaded with no audit trail",
     "nist": "PR.PS-04", "risk": "HIGH"},
    # Firmware
    {"id": "ST-005", "component": "Firmware", "stride": "Tampering",
     "threat": "Malicious firmware installed via OTA update",
     "scenario": "Attacker intercepts OTA channel and delivers unsigned malicious firmware",
     "nist": "PR.PS-02", "risk": "CRITICAL"},
    {"id": "ST-006", "component": "Firmware", "stride": "Information Disclosure",
     "threat": "Hardcoded credentials in firmware",
     "scenario": "Attacker extracts and reverse engineers firmware to find hardcoded secrets",
     "nist": "PR.DS-01", "risk": "CRITICAL"},
    {"id": "ST-007", "component": "Firmware", "stride": "Denial of Service",
     "threat": "Firmware crash via malformed input",
     "scenario": "Attacker sends malformed packets causing firmware crash",
     "nist": "DE.CM-01", "risk": "HIGH"},
    {"id": "ST-008", "component": "Firmware", "stride": "Elevation of Privilege",
     "threat": "Firmware runs all services as root",
     "scenario": "Compromised service escalates to full device control",
     "nist": "PR.AA-05", "risk": "HIGH"},
    {"id": "ST-009", "component": "Firmware", "stride": "Repudiation",
     "threat": "Firmware actions not logged",
     "scenario": "Attacker modifies device configuration with no log entry",
     "nist": "PR.PS-04", "risk": "HIGH"},
    # JTAG/UART
    {"id": "ST-010", "component": "JTAG/UART Interface", "stride": "Spoofing",
     "threat": "Attacker impersonates authorized debugger",
     "scenario": "Attacker connects unauthorized JTAG debugger gaining full memory access",
     "nist": "PR.AA-03", "risk": "CRITICAL"},
    {"id": "ST-011", "component": "JTAG/UART Interface", "stride": "Tampering",
     "threat": "JTAG used to modify firmware in memory",
     "scenario": "Attacker patches running firmware via JTAG to disable security controls",
     "nist": "PR.PS-01", "risk": "CRITICAL"},
    {"id": "ST-012", "component": "JTAG/UART Interface", "stride": "Information Disclosure",
     "threat": "JTAG exposes full memory contents",
     "scenario": "Attacker dumps entire device memory extracting credentials and keys",
     "nist": "PR.DS-01", "risk": "CRITICAL"},
    {"id": "ST-013", "component": "JTAG/UART Interface", "stride": "Elevation of Privilege",
     "threat": "UART shell grants root access",
     "scenario": "Attacker connects to UART port and accesses root shell with no authentication",
     "nist": "PR.AA-01", "risk": "CRITICAL"},
    # Local Network API
    {"id": "ST-014", "component": "Local Network API", "stride": "Spoofing",
     "threat": "Attacker impersonates legitimate admin",
     "scenario": "Attacker uses stolen or default credentials to authenticate as administrator",
     "nist": "PR.AA-01", "risk": "HIGH"},
    {"id": "ST-015", "component": "Local Network API", "stride": "Tampering",
     "threat": "API accepts unauthorized configuration changes",
     "scenario": "Attacker sends crafted API requests to modify device configuration",
     "nist": "PR.AA-05", "risk": "HIGH"},
    {"id": "ST-016", "component": "Local Network API", "stride": "Information Disclosure",
     "threat": "API returns sensitive data over HTTP",
     "scenario": "Local API transmits credentials in plaintext over unencrypted HTTP",
     "nist": "PR.DS-02", "risk": "HIGH"},
    {"id": "ST-017", "component": "Local Network API", "stride": "Denial of Service",
     "threat": "API flooded with requests causing outage",
     "scenario": "Attacker floods local API with requests causing device unavailability",
     "nist": "DE.CM-01", "risk": "MEDIUM"},
    {"id": "ST-018", "component": "Local Network API", "stride": "Repudiation",
     "threat": "API calls not logged",
     "scenario": "Attacker makes unauthorized configuration changes with no audit log",
     "nist": "PR.PS-04", "risk": "HIGH"},
    # Cloud Backend
    {"id": "ST-019", "component": "Cloud Backend", "stride": "Spoofing",
     "threat": "Attacker impersonates cloud backend",
     "scenario": "Attacker performs man-in-the-middle attack presenting fake cloud server",
     "nist": "PR.DS-02", "risk": "HIGH"},
    {"id": "ST-020", "component": "Cloud Backend", "stride": "Tampering",
     "threat": "Commands from cloud modified in transit",
     "scenario": "Attacker intercepts and modifies commands sent from cloud to device",
     "nist": "PR.DS-02", "risk": "HIGH"},
    {"id": "ST-021", "component": "Cloud Backend", "stride": "Information Disclosure",
     "threat": "Device telemetry intercepted in transit",
     "scenario": "Attacker intercepts unencrypted telemetry data",
     "nist": "PR.DS-02", "risk": "MEDIUM"},
    {"id": "ST-022", "component": "Cloud Backend", "stride": "Denial of Service",
     "threat": "Cloud backend overwhelmed cutting off device",
     "scenario": "Attacker disrupts cloud backend severing device management",
     "nist": "DE.CM-01", "risk": "MEDIUM"},
    # Firmware Update
    {"id": "ST-023", "component": "Firmware Update", "stride": "Spoofing",
     "threat": "Attacker impersonates firmware update server",
     "scenario": "Attacker sets up rogue update server tricking device into downloading malware",
     "nist": "PR.DS-02", "risk": "CRITICAL"},
    {"id": "ST-024", "component": "Firmware Update", "stride": "Tampering",
     "threat": "Firmware image modified during download",
     "scenario": "Attacker performs man-in-the-middle attack modifying firmware in transit",
     "nist": "PR.PS-02", "risk": "CRITICAL"},
    {"id": "ST-025", "component": "Firmware Update", "stride": "Denial of Service",
     "threat": "Update server made unavailable",
     "scenario": "Attacker disrupts update server preventing security patches reaching devices",
     "nist": "PR.PS-02", "risk": "MEDIUM"},
    {"id": "ST-026", "component": "Firmware Update", "stride": "Elevation of Privilege",
     "threat": "Update mechanism exploited for code execution",
     "scenario": "Attacker exploits update parser vulnerability to execute arbitrary code",
     "nist": "PR.AA-05", "risk": "CRITICAL"},
]

# ── Helper functions ──────────────────────────────────────────────────────────
def get_risk_color(risk):
    colors = {
        "CRITICAL": "#ff4444",
        "HIGH":     "#ff8800",
        "MEDIUM":   "#ccaa00",
        "LOW":      "#44bb44"
    }
    return colors.get(risk, "#ffffff")

def get_stride_color(stride):
    colors = {
        "Spoofing":              "#8B0000",
        "Tampering":             "#CC4400",
        "Repudiation":           "#6600CC",
        "Information Disclosure":"#0066CC",
        "Denial of Service":     "#CC6600",
        "Elevation of Privilege":"#006600"
    }
    return colors.get(stride, "#333333")

# ── Count threats ─────────────────────────────────────────────────────────────
risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
stride_counts = {
    "Spoofing": 0, "Tampering": 0, "Repudiation": 0,
    "Information Disclosure": 0, "Denial of Service": 0,
    "Elevation of Privilege": 0
}
for t in threats:
    risk_counts[t["risk"]] += 1
    stride_counts[t["stride"]] += 1

date_str = datetime.datetime.now().strftime("%B %d, %Y")

# ── Generate HTML ─────────────────────────────────────────────────────────────
html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>STRIDE Threat Model Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            background: #f5f5f5;
            color: #333;
        }}
        h1 {{ color: #1B3A6B; border-bottom: 3px solid #1B3A6B; padding-bottom: 10px; }}
        h2 {{ color: #2E75B6; margin-top: 30px; }}
        .meta {{
            background: #1B3A6B; color: white;
            padding: 15px 20px; border-radius: 6px; margin-bottom: 25px;
        }}
        .meta p {{ margin: 4px 0; }}
        .grid {{
            display: grid; grid-template-columns: repeat(4, 1fr);
            gap: 15px; margin-bottom: 20px;
        }}
        .grid2 {{
            display: grid; grid-template-columns: repeat(3, 1fr);
            gap: 15px; margin-bottom: 30px;
        }}
        .card {{
            padding: 20px; border-radius: 8px;
            text-align: center; color: white; font-weight: bold;
        }}
        .card .number {{ font-size: 2.5em; display: block; }}
        table {{
            width: 100%; border-collapse: collapse;
            background: white; border-radius: 8px;
            overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }}
        th {{
            background: #1B3A6B; color: white;
            padding: 12px 15px; text-align: left; font-size: 0.9em;
        }}
        td {{ padding: 10px 15px; border-bottom: 1px solid #eee; font-size: 0.85em; }}
        tr:last-child td {{ border-bottom: none; }}
        tr:hover td {{ background: #f9f9f9; }}
        .badge {{
            padding: 3px 8px; border-radius: 10px;
            color: white; font-weight: bold;
            font-size: 0.8em; display: inline-block;
        }}
        .footer {{
            margin-top: 40px; text-align: center;
            color: #888; font-size: 0.85em;
            border-top: 1px solid #ddd; padding-top: 15px;
        }}
    </style>
</head>
<body>
    <h1>STRIDE Threat Model Report — Embedded IoT Device</h1>
    <div class="meta">
        <p><strong>Author:</strong> Mckintosh Mpumelelo Moyo</p>
        <p><strong>Program:</strong> MS Cybersecurity — Yeshiva University, Katz School</p>
        <p><strong>Methodology:</strong> Microsoft STRIDE | Framework: NIST CSF 2.0</p>
        <p><strong>Generated:</strong> {date_str}</p>
    </div>

    <h2>Risk Level Summary</h2>
    <div class="grid">
        <div class="card" style="background:#ff4444;">
            <span class="number">{risk_counts['CRITICAL']}</span>CRITICAL
        </div>
        <div class="card" style="background:#ff8800;">
            <span class="number">{risk_counts['HIGH']}</span>HIGH
        </div>
        <div class="card" style="background:#ccaa00;">
            <span class="number">{risk_counts['MEDIUM']}</span>MEDIUM
        </div>
        <div class="card" style="background:#44bb44;">
            <span class="number">{risk_counts['LOW']}</span>LOW
        </div>
    </div>

    <h2>STRIDE Category Breakdown</h2>
    <div class="grid2">
        <div class="card" style="background:#8B0000;">
            <span class="number">{stride_counts['Spoofing']}</span>Spoofing
        </div>
        <div class="card" style="background:#CC4400;">
            <span class="number">{stride_counts['Tampering']}</span>Tampering
        </div>
        <div class="card" style="background:#6600CC;">
            <span class="number">{stride_counts['Repudiation']}</span>Repudiation
        </div>
        <div class="card" style="background:#0066CC;">
            <span class="number">{stride_counts['Information Disclosure']}</span>Info Disclosure
        </div>
        <div class="card" style="background:#CC6600;">
            <span class="number">{stride_counts['Denial of Service']}</span>Denial of Service
        </div>
        <div class="card" style="background:#006600;">
            <span class="number">{stride_counts['Elevation of Privilege']}</span>Elevation of Priv
        </div>
    </div>

    <h2>Full Threat Register</h2>
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Component</th>
                <th>STRIDE</th>
                <th>Threat</th>
                <th>Attack Scenario</th>
                <th>NIST Control</th>
                <th>Risk</th>
            </tr>
        </thead>
        <tbody>
"""

for t in threats:
    html += f"""
            <tr>
                <td><strong>{t['id']}</strong></td>
                <td>{t['component']}</td>
                <td><span class="badge" style="background:{get_stride_color(t['stride'])}">{t['stride']}</span></td>
                <td>{t['threat']}</td>
                <td style="font-size:0.82em">{t['scenario']}</td>
                <td><strong>{t['nist']}</strong></td>
                <td><span class="badge" style="background:{get_risk_color(t['risk'])}">{t['risk']}</span></td>
            </tr>
"""

html += """
        </tbody>
    </table>
    <div class="footer">
        <p>Generated by STRIDE Threat Model Report Generator</p>
        <p>Mckintosh Mpumelelo Moyo — MS Cybersecurity, Yeshiva University</p>
        <p>Methodology: Microsoft STRIDE | Framework: NIST CSF 2.0</p>
    </div>
</body>
</html>
"""

# ── Save report ───────────────────────────────────────────────────────────────
output_file = "report/stride-threat-report.html"
with open(output_file, "w") as f:
    f.write(html)

print("=" * 55)
print("  STRIDE Threat Model Report — Generated!")
print("=" * 55)
print(f"  Date:            {date_str}")
print(f"  Total Threats:   {len(threats)}")
print(f"  CRITICAL:        {risk_counts['CRITICAL']}")
print(f"  HIGH:            {risk_counts['HIGH']}")
print(f"  MEDIUM:          {risk_counts['MEDIUM']}")
print(f"  LOW:             {risk_counts['LOW']}")
print("=" * 55)
print(f"  Report saved to: {output_file}")
print("=" * 55)