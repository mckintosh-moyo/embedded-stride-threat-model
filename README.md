# Embedded Systems STRIDE Threat Model

A structured threat model for embedded IoT devices using the STRIDE
methodology, mapped to NIST CSF 2.0 controls.

Built by Mckintosh Mpumelelo Moyo — MS Cybersecurity, Yeshiva University

---

## What This Project Is

![STRIDE Threat Model Demo](demo.gif)

This project applies the STRIDE threat modeling framework to a generic
embedded IoT device — the type of device used in smart building
automation, industrial control systems, and connected hardware platforms.

STRIDE stands for Spoofing, Tampering, Repudiation, Information
Disclosure, Denial of Service, and Elevation of Privilege. It provides
a structured way to identify every possible attack vector against a
system before it is deployed.

This threat model covers the full device architecture — from firmware
and debug interfaces to network communication and cloud backend
connectivity — and maps every identified threat to a specific NIST
CSF 2.0 control and mitigation recommendation.

---

## Repository Structure

| Folder | Contents |
|---|---|
| `threat-model/` | STRIDE analysis tables mapping threats to device components |
| `mitigations/` | Mitigation recommendations for each identified threat |
| `data-flow-diagram/` | Data flow diagram of the embedded device architecture |
| `report/` | Auto-generated HTML threat report |

---

## Device Architecture Covered

The threat model covers the following components and data flows:

- Firmware update mechanism
- JTAG/UART debug interfaces
- Local network communication (HTTP/HTTPS APIs)
- Cloud backend connectivity
- Mobile app / management interface
- Physical hardware layer
- Bootloader and secure boot process

---

## STRIDE Threat Categories

| Letter | Threat | Description |
|---|---|---|
| S | Spoofing | Impersonating a legitimate device, user, or service |
| T | Tampering | Unauthorized modification of firmware, data, or configuration |
| R | Repudiation | Performing actions without a traceable audit trail |
| I | Information Disclosure | Exposing sensitive data to unauthorized parties |
| D | Denial of Service | Disrupting device availability or functionality |
| E | Elevation of Privilege | Gaining unauthorized access beyond intended permissions |

---

## Frameworks Used

- NIST Cybersecurity Framework (CSF) 2.0
- Microsoft STRIDE Threat Modeling Methodology
- OWASP Embedded Application Security Project
- NIST SP 800-82 Rev 3 — Guide to OT/ICS Security

---

## Industry Application

This threat model is applicable to any organization developing or
deploying embedded hardware products — including smart building
automation systems, medical devices, industrial control systems,
and IoT platforms.

It supports security engineering and GRC teams performing threat
analysis, vulnerability triage, and secure design reviews for
embedded platforms.

---

## Author

**Mckintosh Mpumelelo Moyo**
MS Cybersecurity — Yeshiva University, Katz School of Science and Health
[LinkedIn](https://www.linkedin.com/in/mckintosh-moyo)
[Project 1 — Hardware Security Assessment Framework](https://github.com/mckintosh-moyo/embedded-hardware-security-assessment)