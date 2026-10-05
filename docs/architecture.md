# SentinelDB Architecture & Ingestion Specification

SentinelDB is a Next-Generation Security Information and Event Management (SIEM) and Threat Analytics platform engineered around **MongoDB 7** as its core operational data store, real-time detection engine, and analytics data lake.

```mermaid
flowchart TD
    subgraph Ingestion ["Log Ingestion & Stream Processing"]
        LS["Simulated Network Sources<br/>(syslog, web proxy, firewall, auth)"] --> AGG["Ingestion Agent / Accumulator"]
        AGG -->|Time-Ordered Buckets| TS["events (Time-Series Collection)<br/>ts, meta: {source, host}"]
        AGG -->|Unparsed Text Line| RAW["raw_logs (Regular Collection)<br/>Text Index + 14-Day TTL"]
        AGG -->|Rolling Metric Upsert| IPS["ip_state (State Collection)<br/>riskScore, counters, sets"]
        AGG -->|Lateral Edge Insert| CONN["connections (Edge Collection)<br/>srcHost -> dstHost"]
    end

    subgraph RealTimeDetection ["Real-Time Detection Engine"]
        IPS -->|Change Stream<br/>(insert, update, replace)| CS["Detection Worker Thread"]
        CS -->|Threshold Evaluation<br/>& Threat Intel Join| ALERTS["alerts Collection<br/>(Strict $jsonSchema)"]
        ALERTS -->|Thread-Safe EventBus| SSE["Server-Sent Events (SSE)<br/>/api/stream"]
    end

    subgraph AnalyticsEngine ["High-Performance Analytics"]
        TS -->|Pipeline 9 $merge| HS["hourly_summary<br/>(Materialized)"]
        HS -->|Pipeline 9 Rollup| DS["daily_summary<br/>(Materialized)"]
        CONN -->|Pipeline 5 $graphLookup| GRAPH["Attack Chain Graph Explorer"]
        RAW -->|Pipeline 8 $text + $lookup| SEARCH["Full-Text Investigation"]
        TS -->|Pipelines 1-4, 6-7| DASH["SOC Dashboards & Visualizations"]
    end

    subgraph UserInterface ["Analyst Console"]
        SSE --> UI["React Console (Vite + Recharts + vis-network)"]
        DASH --> UI
        GRAPH --> UI
        SEARCH --> UI
    end
```

---

## 1. Ingestion Architecture: Evaluation vs Production

### Current Deployment (Synthetic Simulation)
In this deployment, log telemetry is generated synthetically to model the enterprise network of **Northwind Logistics**:
- **~120 hosts** spanning five network subnets: `web` (10.10.1.0/24), `app` (10.10.2.0/24), `db` (10.10.3.0/24), `workstation` (10.20.1.0/24), and `vpn` (10.30.1.0/24).
- **80 employee and service accounts** exhibiting normal diurnal enterprise patterns (business-hours authentication bursts, steady web requests, routine firewall flows).
- **Ground-truth attack scenarios**: Labeled multi-stage intrusions covering brute force (T1110), password spraying (T1110.003), network reconnaissance / port scanning (T1046), lateral movement (T1021), and database exfiltration (T1041).
- **Decoys**: Benign noise (mistyped user passwords, IT maintenance sessions, scheduled backup dumps) designed to validate false-positive immunity.

### Production Deployment (Enterprise Ingestion Pipeline)
In production enterprise deployments, synthetic scripts are superseded by decoupled streaming infrastructure:
1. **Endpoint & Perimeter Agents**:
   - **Filebeat / Elastic Agent**: Deployed on Linux/Windows hosts to harvest `/var/log/auth.log`, Windows Event IDs 4624/4625 (Logon/Failed Logon), and Sysmon process events.
   - **Auditd / OSquery**: Captures process execution (`cmd.exe`, `powershell.exe`, `psexec`, `rclone`).
   - **Syslog-ng / Logstash**: Ingests RFC 5424 syslog streams from perimeter firewalls (Palo Alto, Fortinet) and web gateways.
2. **Buffer / Message Broker**:
   - Telemetry streams into **Apache Kafka** partitioned by source category (`telemetry.auth`, `telemetry.firewall`, `telemetry.web`).
   - Kafka decouples bursty ingestion rates (e.g., 50,000+ events/sec during network incidents) from database persistence.
3. **Ingestion Consumers**:
   - Microservices or Kafka Connect MongoDB Sink write batches to MongoDB using ordered=false bulk writes and update `ip_state` accumulator deltas.

---

## 2. Poly-Collection Schema Design Rationale

| Collection | Storage Engine / Type | Primary Purpose | Architectural Justification |
|---|---|---|---|
| `events` | **Time-Series** (`seconds` granularity) | High-volume structured telemetry | Columnar compressed storage (53% space reduction) grouped by `metaField: {source, host}`. |
| `raw_logs` | Regular Collection | Raw message text search & compliance retention | MongoDB time-series does not support `$text` indexes or non-time TTLs. Storing raw logs separately enables an inverted text index and a 14-day automatic purge. |
| `ip_state` | Regular Collection | Real-time state accumulation & change stream source | Time-series collections do not support Change Streams or single-document updates. `ip_state` maintains rolling counters that trigger real-time detection alerts upon update. |
| `connections` | Regular Collection | Network topology graph | Serves as the edge list for `$graphLookup` multi-hop lateral movement reconstruction. |
| `alerts` | Strict `$jsonSchema` | Triaged security alerts | Guaranteed schema validation for MITRE taxonomy, severity tiers, and investigation audit trails. |
| `incidents` | Strict `$jsonSchema` | Escalated security cases | Groups related alerts into actionable incident tickets with assignment and notes. |
| `threat_intel` | Regular (Unique `ip` index) | Threat intelligence feed | Enriches alerts and pipelines via fast `$lookup` queries. |
| `hourly_summary` | Materialized Collection | Dashboard pre-aggregation | Populated via Pipeline 9 `$merge` so dashboards execute in under 2ms without scanning millions of events. |
| `daily_summary` | Materialized Collection | Long-term trend analytics | Aggregated rollup of `hourly_summary` via `$merge`. |

---

## 3. Real-Time Detection Engine Mechanics

1. **Continuous State Updates**: During ingestion, every source IP's metrics (`failedLogins`, `distinctPortsHit`, `distinctUsersTried`, `bytesOutExternal`, `adminLogons`) are merged into `ip_state` using pipeline-style atomic upserts.
2. **Change Stream Watcher**: `detector.py` maintains an active replica set Change Stream (`db.ip_state.watch(...)`) configured with `fullDocument="updateLookup"`.
3. **Rule Evaluation**:
   - **T1110 (Brute Force)**: $\ge 100$ failed logins against $\le 5$ accounts.
   - **T1110.003 (Password Spraying)**: $\ge 15$ distinct accounts attempted with $\le 5$ tries per user.
   - **T1046 (Port Scan)**: $\ge 100$ distinct destination ports probed.
   - **T1021 (Lateral Movement)**: Administrative protocol logons (SSH, RDP, SMB, WinRM) originating from internal servers.
   - **T1041 (Exfiltration)**: Outbound external volume from database servers exceeding 500 MB.
4. **Threat Intel Correlation & Escalation**: The source IP is checked against `threat_intel`. If known malicious, alert severity is automatically elevated by one tier.
5. **Deduplication**: Alerts are deduplicated per `(ruleId, srcIp)` while in `open` or `acknowledged` status.
6. **SSE Distribution**: New alerts are dispatched thread-safely via `EventBus` to connected SOC analyst browser sessions.
