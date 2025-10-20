# SOC Automation Home Lab (Damin Mohsin)

## Table of Contents
- [Overview](#overview)
- [Objectives](#objectives)
- [System Architecture](#system-architecture)
- [Components](#components)
- [Key Configuration](#key-configuration)
- [Network & Security Considerations](#network--security-considerations)
- [Data Ingestion & Logging Pipeline](#data-ingestion--logging-pipeline)
- [Detection Engineering & MITRE Mapping](#detection-engineering--mitre-mapping)
- [SOAR Automation Workflows](#soar-automation-workflows)
- [Testing & Red Team Simulation](#testing--red-team-simulation)
- [Metrics & KPIs](#metrics--kpis)
- [Incident Response Operating Model](#incident-response-operating-model)
- [Roles & Responsibilities](#roles--responsibilities)
- [Lessons Learned & Future Enhancements](#lessons-learned--future-enhancements)
- [Current Playbooks](#current-playbooks)
- [Resources](#resources)

---

## Overview
This lab demonstrates building a small Security Operations Center (SOC) using open-source tools and automation. It uses:
- Windows client with Sysmon for telemetry
- Wazuh manager for ingestion and detection
- Shuffle (SOAR) for orchestration and automation
- TheHive for case management
- VirusTotal for enrichment
- Email for analyst notifications

Events from Sysmon -> Wazuh (alerts) -> Shuffle (webhook & enrichment) -> TheHive (cases) and email notifications. The lab documents architecture, detection engineering, workflows, testing methodology, metrics, and operational guidance.

---

## Objectives
1. Provide hands-on SOC experience with modern tooling and automation.
2. Integrate Wazuh, Sysmon, Shuffle, TheHive and VirusTotal for detection and enrichment.
3. Build detection rules mapped to MITRE ATT&CK (e.g., T1003).
4. Implement SOAR playbooks to enrich alerts, open cases, and notify analysts.
5. Align incident response with NIST SP 800‑61 guidance.

---

## System Architecture
High-level flow:
1. Windows 10 client with Sysmon generates telemetry.
2. Wazuh manager ingests logs, runs detection rules, and generates alerts.
3. Wazuh forwards matching alerts to Shuffle via webhook.
4. Shuffle enriches alerts (VirusTotal), creates a case in TheHive, and sends email notifications.
5. Analysts triage in TheHive and may trigger response actions via Shuffle back to Wazuh.

(Place an architectural diagram here in the final deliverable showing endpoints, Wazuh, Shuffle, TheHive, and email).

---

## Components

Component | Role & Deployment
---|---
Windows Client (Wazuh agent) | Windows 10 VM with Sysmon installed (Sysmon64.exe -i sysmonconfig.xml). Sysmon logs process creation, file & network events and forwards to Wazuh agent.
Wazuh Manager / Indexer | Ubuntu 22.04 (8 GB RAM, 50 GB disk). Parses Sysmon logs, applies rules and generates alerts. Includes Filebeat and Elasticsearch for long-term retention and dashboards.
Shuffle (SOAR) | Cloud-hosted Shuffle instance (shuffler.io). Receives alerts via webhook and executes playbooks (extraction, enrichment, TheHive integration, email).
TheHive | Case management platform installed via StrangeBee repo. Backed by Cassandra & Elasticsearch, default accessible on port 9000.
Email Server | SMTP integration in Shuffle used to notify analysts.

---

## Key Configuration
- Sysmon: tuned configuration for comprehensive logging (process, file, registry, network).
- Wazuh agent: forwards Sysmon logs to manager; ossec.conf configured to archive logs (logall/logall_json).
- Custom Wazuh rule file (local_rules.xml) contains detection logic (e.g., Mimikatz detection).
- Shuffle workflows: webhook trigger, regex extraction node, VirusTotal enrichment node, TheHive integration, email node.
- Wazuh integration filtered by rule_id (e.g., 100002) to forward only relevant alerts.

Example Sysmon install:
```powershell
Sysmon64.exe -i sysmonconfig.xml
```

Example Regex used in Shuffle:
```
SHA256=([0-9A-Fa-f]{64})
```

Example Wazuh rule (conceptual snippet):
```xml
<group name="local">
  <rule id="100002" level="15">
    <if_sid>100000</if_sid>
    <field name="win.eventdata.originalFileName">mimikatz.exe</field>
    <description>Credential dumping - Mimikatz detected (T1003)</description>
    <mitre>T1003</mitre>
  </rule>
</group>
```

---

## Network & Security Considerations
- Servers hosted on separate droplets with firewall restrictions (SSH limited to analyst IP).
- Expose only required ports (e.g., 443 for Wazuh dashboard, 9000 for TheHive).
- Use TLS certificates in production to secure communications.
- Agents use registration keys; TheHive and Shuffle use API keys.
- Ensure proper access controls and rotate credentials/API keys.

---

## Data Ingestion & Logging Pipeline
- Sysmon provides high-fidelity telemetry (process creation, file changes, network connections).
- Wazuh agent forwards Sysmon logs to the manager; manager archives full logs (logall/logall_json).
- Filebeat ships archived logs to Elasticsearch for long-term retention and querying.
- Wazuh runs alert rules against events and forwards matching alerts to Shuffle via webhook integration.

---

## Detection Engineering & MITRE Mapping
- Custom Wazuh rule (ID 100002) detects Mimikatz by matching the Sysmon originalFileName metadata rather than only the process name (detects renamed binaries).
- Rule fields: severity, description, MITRE mapping (T1003), context for triage.
- Additional detection ideas: registry modifications, LSASS access, anomalous PowerShell usage.
- Maintain severity, description and MITRE tags for each rule for consistent triage and reporting.

---

## SOAR Automation Workflows

Workflow steps:
1. Webhook Trigger: Shuffle receives Wazuh JSON alert.
2. Regex Extraction: Extract SHA-256 using `SHA256=([0-9A-Fa-f]{64})`.
3. VirusTotal Enrichment: Query VirusTotal v3 API with the extracted hash to get reputation and detection counts.
4. TheHive Alert Creation: Create an alert in TheHive containing title, severity, summary, MITRE tags (e.g., T1003), and sourceRef (Wazuh rule 100002).
5. Email Notification: Send an email summary to analysts (host, hash, VirusTotal detections).
6. Optional Response Action: Call Wazuh API to quarantine or remediate the endpoint (requires proper approvals).

Implementation notes:
- Use regex capture groups in Shuffle for reliable extraction.
- Use environment variables for API keys and endpoints.
- Map detection severity consistently to TheHive severity values.
- Include observables (e.g., SHA-256) and MITRE tags in the TheHive payload for better correlation.

---

## Testing & Red Team Simulation

Test scenario (credential dumping):
- Rename Mimikatz binary (e.g., notepad.exe) and execute on the Windows host.
- Sysmon logs original file name; Wazuh rule matches mimikatz.exe in metadata and generates alert (level 15).
- Wazuh forwards alert to Shuffle; Shuffle enriches via VirusTotal and creates a case in TheHive; analysts receive email.
- Validates end-to-end detection, enrichment, case creation, and notification.

Additional testing:
- Simulate lateral movement (Pass-the-Hash), privilege escalation (SeDebugPrivilege), persistence (run keys).
- Use Atomic Red Team or Caldera to automate scenarios and validate detection coverage.

---

## Metrics & Key Performance Indicators (KPIs)
Track:
- Mean Time to Detect (MTTD): alert creation timestamp - event start timestamp.
- Mean Time to Respond (MTTR): time from detection to containment/resolution.
- Alert Volume Reduction: number of alerts suppressed or auto-closed after enrichment.
- SOAR Workflow Success Rate: percent of alerts processed without errors.
- Case Creation Latency: time from Wazuh alert to TheHive case creation.
- False Positive Rate: percent of alerts that are not malicious.

Benchmarks:
- MTTD: target between 30 minutes and 4 hours (high-performing orgs).
- MTTR: industry 2–4 hours; automation should reduce MTTR considerably.

---

## Incident Response Operating Model
Aligned to NIST SP 800‑61 and CSF 2.0.

NIST Phase | Lab Implementation
---|---
Preparation | Build VMs, install Sysmon/Wazuh/TheHive/Shuffle, develop detection rules, configure workflows, define communications, generate API keys.
Detection & Analysis | Wazuh applies rules and generates alerts; Shuffle enriches and creates cases in TheHive for analyst triage.
Containment, Eradication & Recovery | Analysts can trigger remediation (quarantine file, disable account); document actions in TheHive and restore systems.
Post-Incident Activity | Conduct post-mortems in TheHive, update detection rules and playbooks, review metrics to improve MTTD/MTTR.

Incident response steps:
1. Preparation — documentation, runbooks, training, backups.
2. Identification — triage alerts using Wazuh + Shuffle enrichment.
3. Containment — isolate or remediate via Shuffle triggered actions (with approvals).
4. Eradication — remove persistence and clean host.
5. Recovery — restore services and monitor for re-infection.
6. Lessons Learned — update rules and playbooks.

---

## Roles & Responsibilities
- SOC Analyst: Triage in TheHive, validate enrichment, escalate incidents, document findings.
- SOAR Engineer: Maintain Shuffle workflows and integrations, reduce false positives.
- Detection Engineer: Develop and maintain Wazuh rules, map to MITRE.
- Incident Response Lead: Coordinate response, stakeholder communications, compliance.
- Management & Compliance: Review metrics, approve incident response plans and changes.

---

## Lessons Learned & Future Enhancements

Key lessons:
- High-fidelity telemetry (Sysmon) is essential but must be tuned to manage storage.
- Using metadata fields (originalFileName) reduces false negatives for renamed binaries.
- Automation reduces manual effort and MTTR, but governance is critical.
- Documentation and post-incident reviews help keep playbooks and rules current.

Planned enhancements:
1. Expand detection coverage across ATT&CK techniques (lateral movement, privilege escalation).
2. Add sensors (Zeek) and rule portability (Sigma).
3. Add additional enrichment sources (AbuseIPDB, OTX).
4. Implement analyst feedback loops in Shuffle for false positive marking.
5. Automate containment via endpoint management (WinRM/SSH) subject to approvals.
6. Deploy continuous testing (Atomic Red Team) for regression and MTTD/MTTR measurement.

---

## Current Playbooks
- Credential Dumping (T1003) — Triggered by Wazuh rule 100002 when Sysmon detects mimikatz.exe. Shuffle enriches, creates TheHive case, notifies analysts; optional isolation and credential reset.
- Malicious PowerShell (Future) — Detect encoded commands/AMSI bypass patterns; tag with T1086; terminate process and create case.
- Persistence via Run Keys (Future) — Detect Run key creation, extract registry path, create case, and optionally remove the registry value.

---

## Resources
- Wazuh Documentation — Installation, agent setup, alert rules, integrations.
- TheHive (StrangeBee) — TheHive 5 docs, Cortex analyzers/responders.
- Shuffle (shuffler.io) — Documentation & tutorials for playbook building.
- MISP — Threat intelligence sharing and API documentation.
- Security Onion — NSM deployment (Suricata/Zeek).
- Suricata — IDS/NSM engine docs and tuning.
- Filebeat / Elastic Stack — Log shipping, parsing, and retention.
- MITRE ATT&CK & ATT&CK Navigator — Mapping detections to techniques.
- NIST SP 800-61 Rev. 3 — Incident response lifecycle and playbook guidance.
- CISA — Incident & vulnerability response playbooks.
- VirusTotal API (v3) — File/URL/domain reputation API.

