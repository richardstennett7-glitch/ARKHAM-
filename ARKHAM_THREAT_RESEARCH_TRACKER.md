# ARKHAM Security Systems — Threat Research Tracker

**Last Updated:** 2026-02-27
**Maintained by:** ARKHAM Security Research Team

This document tracks all threat categories covered across every research session. Its purpose is to ensure comprehensive coverage, prevent duplication of effort, and provide a verifiable audit trail of all training data delivered to the ARKHAM systems.

---

## Session Index

| Session | Date | File | Patterns Delivered | Systems Covered |
|---|---|---|---|---|
| Session 2 | 2026-02-27 | `ARKHAM_TRAINING_DATA_2026_02_27.md` | 90 (across 3 systems) | Firewall, Workforce, RoboShield |
| Session 1 | 2026-02-20 | `ARKHAM_TRAINING_DATA_2026_02_20.md` | 44 (across 3 systems) | Firewall, Workforce, RoboShield |

---

## Session 2 — 2026-02-27

**File:** `ARKHAM_TRAINING_DATA_2026_02_27.md`
**Total Patterns:** 90 unique threat patterns across 3 ARKHAM systems

### ARKHAM Firewall (33 Patterns)

| Pattern ID | Threat Category | Severity |
|---|---|---|
| FW-025 | OAuth Device Flow Phishing | Critical |
| FW-026 | HTTP/2 Rapid Reset DoS | Critical |
| FW-027 | Web Cache Deception | High |
| FW-028 | DNS Rebinding | High |
| FW-029 | Subdomain Takeover | High |
| FW-030 | Open Redirect | Medium |
| FW-031 | Path Traversal | High |
| FW-032 | Race Condition (TOCTOU) | High |
| FW-033 | IDOR (Insecure Direct Object Reference) | High |
| FW-034 | CORS Misconfiguration | High |
| FW-035 | HTTP Parameter Pollution | Medium |

### ARKHAM Workforce (24 Patterns)

| Pattern ID | Threat Category | Severity |
|---|---|---|
| WF-013 | Many-Shot Jailbreaking | High |
| WF-014 | Adversarial Suffix Attack | Critical |
| WF-015 | Model Inversion | High |
| WF-016 | Membership Inference | Medium |
| WF-017 | Context Window Overflow | Medium |
| WF-018 | System Prompt Extraction | High |
| WF-019 | Data Poisoning via Fine-Tuning | Critical |
| WF-020 | Shadow AI | High |

### ARKHAM RoboShield (24 Patterns)

| Pattern ID | Threat Category | Severity |
|---|---|---|
| RS-014 | Wi-Fi Deauthentication Attack | High |
| RS-015 | Bluetooth Spoofing | High |
| RS-016 | CAN Bus Injection | Critical |
| RS-017 | Power Line Communication Attack | Medium |
| RS-018 | Thermal Sensor Spoofing | High |
| RS-019 | Time-of-Flight Sensor Spoofing | High |
| RS-020 | Map Poisoning (SLAM Attack) | Critical |
| RS-021 | Fleet Management API Attack | Critical |

---

## Session 1 — 2026-02-20

**File:** `ARKHAM_TRAINING_DATA_2026_02_20.md`
**Total Patterns:** 44 unique threat patterns across 3 ARKHAM systems

### ARKHAM Firewall (24 Patterns)

| Pattern ID | Threat Category | Severity |
|---|---|---|
| FW-001 | LDAP Injection — Filter Manipulation | High |
| FW-002 | LDAP Injection — Blind Boolean-Based | High |
| FW-003 | XXE Injection — File Read | Critical |
| FW-004 | XXE Injection — Out-of-Band via SVG Upload | High |
| FW-005 | SSRF — Cloud Metadata Endpoint Access | High |
| FW-006 | SSRF — Internal Network Scanning via PDF Generator | High |
| FW-007 | HTTP Request Smuggling — CL.TE | Critical |
| FW-008 | HTTP Request Smuggling — TE.CL | Critical |
| FW-009 | Insecure Deserialization — Python Pickle RCE | Critical |
| FW-010 | Insecure Deserialization — Java Object Injection | Critical |
| FW-011 | GraphQL Injection — Introspection Abuse | High |
| FW-012 | GraphQL Injection — Batching Attack (DoS) | Medium |
| FW-013 | CRLF Injection — HTTP Response Splitting | Medium |
| FW-014 | Server-Side Template Injection (SSTI) — Jinja2 | High |
| FW-015 | Server-Side Template Injection (SSTI) — Twig/PHP | High |
| FW-016 | NoSQL Injection — MongoDB Authentication Bypass | High |
| FW-017 | NoSQL Injection — MongoDB `$where` Operator Injection | High |
| FW-018 | WAF Bypass — Unicode Homoglyph Substitution | High |
| FW-019 | JWT Attack — Algorithm Confusion (RS256 to HS256) | Critical |
| FW-020 | JWT Attack — `none` Algorithm | Critical |
| FW-021 | WebSocket Hijacking — Cross-Site WebSocket Hijacking (CSWH) | High |
| FW-022 | Prototype Pollution — JavaScript Object Injection | High |
| FW-023 | ReDoS — Catastrophic Backtracking | Medium |
| FW-024 | OAuth/OIDC Token Theft — Redirect URI Manipulation | Critical |

### ARKHAM Workforce (12 Patterns)

| Pattern ID | Threat Category | Severity |
|---|---|---|
| WF-001 | Memory Poisoning — Long-Term Context Manipulation | Critical |
| WF-002 | Goal Hijacking — Subtle Objective Drift | High |
| WF-003 | Tool Poisoning — Malicious Tool Definition | Critical |
| WF-004 | Multi-Agent Prompt Injection — Inter-Agent Attack | High |
| WF-005 | RAG Poisoning — Knowledge Base Contamination | High |
| WF-006 | Indirect Prompt Injection — Email-Borne Attack | High |
| WF-007 | AI Supply Chain Attack — Model Substitution | Critical |
| WF-008 | Hallucination Exploitation — False Security Advice | Medium |
| WF-009 | Token Smuggling — Unicode Homoglyph Attack | Medium |
| WF-010 | Persona Hijacking — Roleplay-Based Jailbreak | High |
| WF-011 | Capability Probing — Systematic Boundary Testing | Medium |
| WF-012 | Agent Impersonation — Fake Orchestrator Attack | Critical |

### ARKHAM RoboShield (13 Patterns)

| Pattern ID | Threat Category | Severity |
|---|---|---|
| RS-001 | Ultrasonic Sensor Spoofing — Acoustic Injection | High |
| RS-002 | ROS2 Topic Injection — Unauthorised Navigation Command | Critical |
| RS-003 | Waypoint Injection — Navigation Plan Manipulation | High |
| RS-004 | Actuator Command Flooding — Motor DoS | Medium |
| RS-005 | Emergency Stop Signal Spoofing — False E-Stop | Critical |
| RS-006 | Robot Identity Spoofing — MAC Address Cloning | Critical |
| RS-007 | Encoder Spoofing — Wheel Odometry Manipulation | High |
| RS-008 | Pressure Sensor Tampering — Force Feedback Manipulation | High |
| RS-009 | DDS (Data Distribution Service) Attack — Topic Hijacking | Critical |
| RS-010 | Collaborative Robot Safety Zone Bypass | Critical |
| RS-011 | NTP Spoofing — Robot Timing Attack | High |
| RS-012 | Physical Adversarial Patch — Visual Sensor Spoofing | High |
| RS-013 | VLA Model Adversarial Input — Action Manipulation | High |

---

## Existing Coverage (Pre-Session 1)

The following threat categories were already present in the ARKHAM codebase prior to Session 1 and are **excluded** from all future research sessions to prevent duplication.

### ARKHAM Firewall (Pre-existing)
Cross-Site Scripting (XSS), SQL Injection, Code Injection, Jailbreak, Data Exfiltration, Malicious URLs, Malicious Code, Prompt Injection.

### ARKHAM Workforce (Pre-existing)
Prompt Injection, Jailbreak Attempts, Data Exfiltration, PII Exposure, System Prompt Leak, Credential Leak, Code Injection, Instruction Override, Context Manipulation.

### ARKHAM RoboShield (Pre-existing)
Command Injection, GPS Spoofing, LiDAR Injection, Camera Feed Manipulation, IMU Spoofing, Firmware Tampering, Safety Limit Override, Motion Anomaly, Unauthorised Access, Communication Tampering.

---

## Notes for Future Sessions

**Session 2 fulfilled all priority areas.**


Session 3 should target a minimum of **180 new patterns** (double the 90 delivered in Session 2, per the recurring research volume preference). All patterns must be entirely new and must not duplicate any category listed in this tracker. Priority areas for Session 3 include:

- **Firewall:** Business logic flaws, mass assignment, XML injection, XSLT injection, host header injection, HTTP response splitting (beyond CRLF), OAuth PKCE bypass, SAML injection, API key leakage, insecure file upload.
- **Workforce:** Prompt injection via tool output, agent loop hijacking, cross-agent data leakage, model watermarking bypass, AI-generated deepfake detection, LLM-assisted social engineering, reward hacking, specification gaming.
- **RoboShield:** MQTT broker attack, OPC-UA exploitation, Modbus injection, DNP3 spoofing, robot arm trajectory manipulation, battery management system attack, charging station spoofing, robot-to-robot communication attack.
