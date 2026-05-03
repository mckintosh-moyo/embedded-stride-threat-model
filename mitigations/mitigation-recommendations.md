# Threat Mitigation Recommendations — Embedded IoT Device
# Author: Mckintosh Mpumelelo Moyo — MS Cybersecurity, Yeshiva University
# Mapped to: NIST CSF 2.0 | OWASP Embedded Application Security

---

## How to Use This Document

This document provides mitigation recommendations for every threat
identified in the STRIDE analysis. Mitigations are grouped by
component and prioritized by risk level.

---

## PRIORITY 1: CRITICAL Threats — Mitigate Immediately

### Bootloader Security (ST-001, ST-002, ST-003)

**M-001 — Implement Secure Boot**
- Enable cryptographic verification of firmware at every boot
- Establish a chain of trust from hardware root of trust to bootloader
- Only allow execution of firmware signed by a trusted key
- NIST Control: PR.PS-05
- Implementation: Use platform-specific secure boot (ARM TrustZone,
  Intel Boot Guard, or equivalent)

**M-002 — Protect Bootloader from Physical Modification**
- Fuse the bootloader into read-only memory after production
- Implement write protection on bootloader storage
- NIST Control: PR.PS-01
- Implementation: Set OTP (One Time Programmable) fuses to lock
  bootloader partition after manufacturing

**M-003 — Encrypt Keys Stored in Bootloader Memory**
- Store all cryptographic keys in a dedicated secure element
- Never store keys in plaintext in bootloader or firmware memory
- NIST Control: PR.DS-01
- Implementation: Use TPM, ARM TrustZone, or dedicated secure
  element (e.g., ATECC608)

---

### JTAG/UART Interface Security (ST-010, ST-011, ST-012, ST-013)

**M-004 — Disable Debug Interfaces in Production**
- JTAG and UART must be completely disabled in production firmware
- Debug features should only be available in development builds
- NIST Control: PR.PS-01, PR.AA-03
- Implementation: Set JTAG disable fuses during production
  programming. Remove UART shell from production firmware build.

**M-005 — Implement Authentication for Debug Access**
- If debug access is required for maintenance, require authentication
- Log all debug interface access attempts
- NIST Control: PR.AA-01, PR.AA-03
- Implementation: Implement challenge-response authentication
  for any authorized debug access in field maintenance scenarios

---

### Firmware Update Security (ST-023, ST-024, ST-026)

**M-006 — Implement Cryptographic Firmware Signing**
- All firmware images must be signed using RSA-2048 or ECDSA-256
- Private signing keys must be stored in an HSM
- Device must verify signature before installing any update
- NIST Control: PR.PS-02, PR.DS-10
- Implementation: Integrate firmware signing into CI/CD pipeline.
  Use asymmetric cryptography — private key in HSM, public key
  fused into device.

**M-007 — Pin Firmware Update Server Certificate**
- Device must verify the identity of the update server
- Implement certificate pinning to prevent rogue update servers
- NIST Control: PR.DS-02
- Implementation: Embed update server's certificate fingerprint
  in firmware. Reject any update server presenting a different
  certificate.

**M-008 — Validate Firmware Before Execution**
- Verify cryptographic hash of firmware after download and before
  installation
- Reject any firmware package that fails integrity verification
- NIST Control: PR.PS-02, PR.DS-10
- Implementation: SHA-256 hash verification after download,
  before writing to flash storage

---

## PRIORITY 2: HIGH Threats — Mitigate Within 30 Days

### Firmware Security (ST-005, ST-006, ST-008, ST-009)

**M-009 — Remove Hardcoded Credentials**
- Audit all firmware for hardcoded passwords, API keys, and tokens
- Replace with secure credential storage in encrypted storage
- NIST Control: PR.DS-01, PR.AA-01
- Implementation: Use secure element or encrypted partition for
  credential storage. Generate unique per-device credentials
  at manufacture.

**M-010 — Implement Least Privilege for Firmware Services**
- All services must run with minimum necessary privileges
- No application service should run as root
- NIST Control: PR.AA-05
- Implementation: Create dedicated service accounts for each
  application component. Use Linux capabilities instead of
  full root access.

**M-011 — Implement Comprehensive Audit Logging**
- Log all authentication events, configuration changes, and errors
- Logs must be tamper-evident and stored securely
- NIST Control: PR.PS-04
- Implementation: Use syslog with remote forwarding to prevent
  log tampering. Implement cryptographic log chaining.

---

### Local Network API Security (ST-014, ST-015, ST-016, ST-018)

**M-012 — Enforce HTTPS for All API Communication**
- Disable all unencrypted HTTP endpoints
- Enforce TLS 1.2 minimum for all API communication
- NIST Control: PR.DS-02
- Implementation: Configure web server to redirect all HTTP
  to HTTPS. Disable TLS 1.0 and 1.1.

**M-013 — Implement Strong API Authentication**
- Require authentication for all API endpoints
- Implement token-based authentication with expiry
- NIST Control: PR.AA-01, PR.AA-05
- Implementation: Implement OAuth 2.0 or API key authentication
  with automatic token rotation every 24 hours.

**M-014 — Implement API Rate Limiting**
- Limit number of requests per IP address per time window
- Block IPs that exceed rate limits automatically
- NIST Control: DE.CM-01
- Implementation: Configure rate limiting at 100 requests per
  minute per IP. Implement exponential backoff for failed
  authentication attempts.

---

### Cloud Backend Security (ST-019, ST-020)

**M-015 — Implement Mutual TLS for Cloud Communication**
- Both device and cloud server must authenticate each other
- Use device certificates issued at manufacture
- NIST Control: PR.DS-02, PR.AA-03
- Implementation: Issue unique X.509 certificates per device
  at manufacture. Implement mutual TLS for all cloud connections.

---

## PRIORITY 3: MEDIUM Threats — Mitigate Within 90 Days

**M-016 — Implement API Denial of Service Protection**
- Deploy rate limiting and request throttling on local API
- Monitor for abnormal traffic patterns
- NIST Control: DE.CM-01
- Implementation: Implement connection limiting at network level.
  Alert on traffic exceeding normal thresholds.

**M-017 — Encrypt All Telemetry Data in Transit**
- All device telemetry sent to cloud must be encrypted
- No sensitive operational data transmitted in plaintext
- NIST Control: PR.DS-02
- Implementation: Enforce TLS for all outbound connections.
  Implement certificate validation.

---

## Mitigation Coverage Summary

| Component | Threats | Mitigations | Coverage |
|---|---|---|---|
| Bootloader | 4 | M-001, M-002, M-003 | 100% |
| Firmware | 5 | M-009, M-010, M-011 | 100% |
| JTAG/UART Interface | 4 | M-004, M-005 | 100% |
| Local Network API | 5 | M-012, M-013, M-014 | 100% |
| Cloud Backend | 4 | M-015, M-017 | 100% |
| Firmware Update | 4 | M-006, M-007, M-008 | 100% |
| **TOTAL** | **26** | **17** | **100%** |