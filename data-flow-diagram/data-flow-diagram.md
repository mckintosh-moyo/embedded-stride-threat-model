# Embedded IoT Device — Data Flow Diagram
# Author: Mckintosh Mpumelelo Moyo — MS Cybersecurity, Yeshiva University
# Format: Text-based Data Flow Diagram (DFD)

---

## System Overview

This diagram describes the data flows of a generic embedded IoT device
used in smart building automation and connected hardware platforms.
It identifies all components, interfaces, and trust boundaries relevant
to the STRIDE threat model.

---

## Components

| Component ID | Component Name | Description |
|---|---|---|
| C-01 | Embedded Device | The physical hardware unit running embedded Linux |
| C-02 | Bootloader | Initializes hardware and loads firmware on startup |
| C-03 | Firmware | The operating software running on the device |
| C-04 | JTAG/UART Interface | Physical debug interface on the hardware |
| C-05 | Local Network API | HTTP/HTTPS API for local management and control |
| C-06 | Cloud Backend | Remote server receiving device telemetry and sending commands |
| C-07 | Mobile/Web App | Management interface used by administrators |
| C-08 | Firmware Update Server | Server hosting firmware images for OTA updates |
| C-09 | Physical Hardware | The device enclosure, ports, and physical components |

---

## Trust Boundaries

| Boundary ID | Boundary Name | Description |
|---|---|---|
| TB-01 | Device Perimeter | Separates internal device components from external interfaces |
| TB-02 | Network Boundary | Separates local network from internet/cloud |
| TB-03 | Physical Boundary | Separates accessible physical interfaces from internal hardware |
| TB-04 | Firmware Boundary | Separates trusted firmware from untrusted update packages |

---

## Data Flows

| Flow ID | Source | Destination | Data | Protocol | Trust Boundary Crossed |
|---|---|---|---|---|---|
| DF-01 | Firmware Update Server | Embedded Device | Firmware image | HTTPS/OTA | TB-01, TB-02 |
| DF-02 | JTAG/UART Interface | Firmware | Debug commands, memory read/write | JTAG/UART | TB-03 |
| DF-03 | Embedded Device | Cloud Backend | Telemetry, status, sensor data | HTTPS | TB-01, TB-02 |
| DF-04 | Cloud Backend | Embedded Device | Commands, configuration updates | HTTPS | TB-01, TB-02 |
| DF-05 | Mobile/Web App | Local Network API | Control commands, configuration | HTTP/HTTPS | TB-01 |
| DF-06 | Local Network API | Embedded Device | Parsed commands, config changes | Internal | TB-01 |
| DF-07 | Bootloader | Firmware | Firmware load and execution | Internal | TB-04 |
| DF-08 | Embedded Device | Mobile/Web App | Device status, logs, alerts | HTTP/HTTPS | TB-01 |

---

## Text-Based Architecture Diagram

+------------------+          +------------------+
|  Firmware Update |          |   Cloud Backend  |
|     Server       |          |                  |
+--------+---------+          +--------+---------+
|  DF-01 (HTTPS)              |  DF-03/04 (HTTPS)
|                             |
v                             v
+--------+-----------------------------+---------+
|                                                 |
|              TRUST BOUNDARY TB-02              |
|                                                 |
|  +------------------------------------------+  |
|  |         EMBEDDED IoT DEVICE              |  |
|  |                                          |  |
|  |  +------------+    +----------------+   |  |
|  |  |  Bootloader|--->|    Firmware    |   |  |
|  |  | (C-02)     |    |    (C-03)      |   |  |
|  |  +------------+    +-------+--------+   |  |
|  |                            |             |  |
|  |                    +-------+--------+   |  |
|  |                    | Local Network  |   |  |
|  |                    |   API (C-05)   |   |  |
|  |                    +----------------+   |  |
|  +------------------------------------------+  |
|         |                        |              |
|    TB-03|                   TB-01|              |
+---------|-----------------------|---------------+
|                       |
+---------+--------+    +---------+--------+
|  JTAG/UART       |    |  Mobile/Web App  |
|  Interface (C-04)|    |  (C-07)          |
+------------------+    +------------------+

---

## Attack Surface Summary

| Interface | Exposed To | Risk Level |
|---|---|---|
| JTAG/UART | Physical attacker | CRITICAL |
| Local Network API | Local network attacker | HIGH |
| OTA Firmware Update | Remote attacker | HIGH |
| Cloud Backend Connection | Remote attacker | MEDIUM |
| Physical Hardware | Physical attacker | HIGH |
| Mobile/Web App | Network attacker | MEDIUM |