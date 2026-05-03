# STRIDE Threat Analysis — Embedded IoT Device
# Author: Mckintosh Mpumelelo Moyo — MS Cybersecurity, Yeshiva University
# Methodology: Microsoft STRIDE Threat Modeling Framework
# Mapped to: NIST CSF 2.0

---

## How to Read This Document

Each threat is identified by:
- Component being attacked
- STRIDE category
- Threat description
- Attack scenario
- NIST CSF 2.0 control that addresses it
- Risk level

---

## COMPONENT 1: Bootloader (C-02)

| Threat ID | STRIDE | Threat | Attack Scenario | NIST Control | Risk |
|---|---|---|---|---|---|
| ST-001 | Tampering | Bootloader modified to load unsigned firmware | Attacker with physical access replaces bootloader with malicious version that skips signature verification | PR.PS-05 | CRITICAL |
| ST-002 | Elevation of Privilege | Bootloader bypass grants root access | Attacker exploits bootloader vulnerability to gain unrestricted root shell before OS loads | PR.AA-05 | CRITICAL |
| ST-003 | Information Disclosure | Bootloader exposes encryption keys in memory | Attacker uses JTAG to dump bootloader memory and extract device encryption keys | PR.DS-01 | HIGH |
| ST-004 | Repudiation | No logging of bootloader events | Malicious firmware loaded with no audit trail — impossible to detect or investigate | PR.PS-04 | HIGH |

---

## COMPONENT 2: Firmware (C-03)

| Threat ID | STRIDE | Threat | Attack Scenario | NIST Control | Risk |
|---|---|---|---|---|---|
| ST-005 | Tampering | Malicious firmware installed via OTA update | Attacker intercepts OTA update channel and delivers unsigned malicious firmware | PR.PS-02 | CRITICAL |
| ST-006 | Information Disclosure | Hardcoded credentials in firmware | Attacker extracts firmware image and reverse engineers it to find hardcoded API keys or passwords | PR.DS-01 | CRITICAL |
| ST-007 | Denial of Service | Firmware crash via malformed input | Attacker sends malformed packets to device API causing firmware crash and device unavailability | DE.CM-01 | HIGH |
| ST-008 | Elevation of Privilege | Firmware runs all services as root | Compromised service escalates to full device control because everything runs with root privileges | PR.AA-05 | HIGH |
| ST-009 | Repudiation | Firmware actions not logged | Attacker modifies device configuration with no log entry — changes undetectable and undeniable | PR.PS-04 | HIGH |

---

## COMPONENT 3: JTAG/UART Interface (C-04)

| Threat ID | STRIDE | Threat | Attack Scenario | NIST Control | Risk |
|---|---|---|---|---|---|
| ST-010 | Spoofing | Attacker impersonates authorized debugger | Attacker connects unauthorized JTAG debugger and gains full read/write access to device memory | PR.AA-03 | CRITICAL |
| ST-011 | Tampering | JTAG used to modify firmware in memory | Attacker patches running firmware in memory via JTAG to disable security controls | PR.PS-01 | CRITICAL |
| ST-012 | Information Disclosure | JTAG exposes full memory contents | Attacker dumps entire device memory via JTAG extracting credentials, keys, and sensitive data | PR.DS-01 | CRITICAL |
| ST-013 | Elevation of Privilege | UART shell grants root access | Attacker connects to UART port and accesses root shell with no authentication required | PR.AA-01 | CRITICAL |

---

## COMPONENT 4: Local Network API (C-05)

| Threat ID | STRIDE | Threat | Attack Scenario | NIST Control | Risk |
|---|---|---|---|---|---|
| ST-014 | Spoofing | Attacker impersonates legitimate admin | Attacker uses stolen or default credentials to authenticate to local API as administrator | PR.AA-01 | HIGH |
| ST-015 | Tampering | API accepts unauthorized configuration changes | Attacker sends crafted API requests to modify device configuration without proper authorization | PR.AA-05 | HIGH |
| ST-016 | Information Disclosure | API returns sensitive data over HTTP | Local API transmits credentials or configuration data in plaintext over unencrypted HTTP | PR.DS-02 | HIGH |
| ST-017 | Denial of Service | API flooded with requests causing outage | Attacker floods local API with requests causing device to become unresponsive | DE.CM-01 | MEDIUM |
| ST-018 | Repudiation | API calls not logged | Attacker makes unauthorized configuration changes via API with no audit log entry created | PR.PS-04 | HIGH |

---

## COMPONENT 5: Cloud Backend Connection (C-06)

| Threat ID | STRIDE | Threat | Attack Scenario | NIST Control | Risk |
|---|---|---|---|---|---|
| ST-019 | Spoofing | Attacker impersonates cloud backend | Attacker performs man-in-the-middle attack presenting fake cloud server to device | PR.DS-02 | HIGH |
| ST-020 | Tampering | Commands from cloud backend modified in transit | Attacker intercepts and modifies commands sent from cloud to device | PR.DS-02 | HIGH |
| ST-021 | Information Disclosure | Device telemetry intercepted in transit | Attacker intercepts unencrypted telemetry data containing sensitive operational information | PR.DS-02 | MEDIUM |
| ST-022 | Denial of Service | Cloud backend overwhelmed cutting off device | Attacker disrupts cloud backend availability severing device management capability | DE.CM-01 | MEDIUM |

---

## COMPONENT 6: Firmware Update Mechanism (C-08)

| Threat ID | STRIDE | Threat | Attack Scenario | NIST Control | Risk |
|---|---|---|---|---|---|
| ST-023 | Spoofing | Attacker impersonates firmware update server | Attacker sets up rogue update server and tricks device into downloading malicious firmware | PR.DS-02 | CRITICAL |
| ST-024 | Tampering | Firmware image modified during download | Attacker performs man-in-the-middle attack and modifies firmware package in transit | PR.PS-02 | CRITICAL |
| ST-025 | Denial of Service | Update server made unavailable | Attacker disrupts update server preventing security patches from reaching devices | PR.PS-02 | MEDIUM |
| ST-026 | Elevation of Privilege | Update mechanism exploited for code execution | Attacker exploits vulnerability in update parser to execute arbitrary code with elevated privileges | PR.AA-05 | CRITICAL |

---

## STRIDE Coverage Summary

| STRIDE Category | Number of Threats Identified |
|---|---|
| Spoofing (S) | 5 |
| Tampering (T) | 7 |
| Repudiation (R) | 3 |
| Information Disclosure (I) | 6 |
| Denial of Service (D) | 5 |
| Elevation of Privilege (E) | 4 |
| **TOTAL** | **26** |

---

## Risk Level Summary

| Risk Level | Count | Threat IDs |
|---|---|---|
| CRITICAL | 11 | ST-001, ST-002, ST-005, ST-006, ST-010, ST-011, ST-012, ST-013, ST-023, ST-024, ST-026 |
| HIGH | 12 | ST-003, ST-004, ST-007, ST-008, ST-009, ST-014, ST-015, ST-016, ST-018, ST-019, ST-020 |
| MEDIUM | 3 | ST-017, ST-021, ST-022, ST-025 |
| LOW | 0 | — |