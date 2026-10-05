import React, { useState } from 'react';

const FAQS = [
  {
    q: 'What is a SIEM and how does SentinelDB operate as a security analytics platform?',
    a: 'A Security Information and Event Management (SIEM) system ingests, normalizes, aggregates, and analyzes security telemetry across an enterprise network. SentinelDB is an architecture where MongoDB 7 serves as the primary operational database, real-time detection engine, and analytics data lake. It correlates raw syslog messages, network flows, and authentication outcomes to detect threats in real time.',
  },
  {
    q: 'How does real-time threat detection work with MongoDB Change Streams?',
    a: 'Instead of constantly polling telemetry tables, SentinelDB maintains an `ip_state` collection containing rolling entity metrics (failed logins, distinct ports, outbound volume, risk score). Ingestion bulk-upserts these state counters. A background detection worker listens to an active change stream on `ip_state`. When document updates match threat thresholds, the engine immediately creates an alert document in the validated `alerts` collection and pushes it to SOC analyst consoles over Server-Sent Events (SSE).',
  },
  {
    q: 'Why does SentinelDB use MongoDB Time-Series collections for telemetry events?',
    a: 'Security telemetry produces high-volume, timestamped, append-only streams. MongoDB 7 time-series collections store documents in columnar compressed buckets ordered by time (`ts`) and grouped by `meta` (source, host). As shown in our benchmarks, this achieves over 50% physical storage reduction and an almost 5x smaller secondary index RAM footprint compared to standard collections.',
  },
  {
    q: 'What are the limitations of Time-Series collections and how does SentinelDB address them?',
    a: 'MongoDB time-series collections do not support: 1) unique indexes, 2) full-text indexes ($text), 3) single-document updates (update_one without multi), and 4) Change Streams. SentinelDB addresses these limitations through a deliberate poly-collection design: telemetry events reside in the time-series `events` collection, raw message text search is handled by `raw_logs` (regular collection with text index and 14-day TTL), and change stream detection is powered by `ip_state`.',
  },
  {
    q: 'Why is raw syslog message text stored in a dedicated raw_logs collection?',
    a: 'Because MongoDB forbids text indexes on time-series collections. By storing the unparsed syslog line in `raw_logs`, SentinelDB can apply an inverted text index (`message_text`) for sub-5ms keyword searches. It also attaches a TTL index (`expireAfterSeconds: 1209600`) to automatically purge raw logs after 14 days, satisfying enterprise data retention compliance.',
  },
  {
    q: 'How does $graphLookup reconstruct multi-hop lateral movement attack chains?',
    a: 'In an intrusion, an adversary typically pivots from a compromised workstation to an internal application server, and finally to a sensitive database. SentinelDB tracks remote-management protocol flows (SSH, RDP, SMB, WinRM) in a dedicated `connections` edge collection. The `$graphLookup` stage starts at an initial compromised host and recursively follows `connectFromField: "dstHost"` to `connectToField: "srcHost"` up to `maxDepth: 5`, recording `depthField: "hop"` to map the complete traversal.',
  },
  {
    q: 'How does SentinelDB detect data exfiltration using $setWindowFields?',
    a: 'Data exfiltration is identified by Pipeline 6 using MongoDB\'s `$setWindowFields` aggregation stage. Outbound firewall transfers from database servers are grouped into 5-minute buckets. The stage calculates a sliding moving average and population standard deviation over the prior 12 buckets. An alert fires when a bucket\'s outbound volume exceeds the dynamic baseline by more than 3 sigma (standard deviations) and transfers over 100MB to external destinations.',
  },
  {
    q: 'How does materialization with $merge optimize dashboard query latency?',
    a: 'Scanning millions of historical events for every dashboard render is computationally inefficient. Pipeline 9 runs an aggregation over the time-series collection and uses `$merge` to upsert precomputed hourly metrics into `hourly_summary`. A secondary rollup materializes `daily_summary`. The dashboard reads pre-aggregated records in under 2ms without putting read locks on the active event ingestion stream.',
  },
  {
    q: 'What do the alert severity levels (Low, Medium, High, Critical) signify for SOC response?',
    a: '• Low: Informational anomalies, single denied connections, or low-frequency password misses (triage within 24h).\n• Medium: Port scans or non-credentialed probes against perimeter endpoints (triage within 4h).\n• High: Confirmed brute-force bursts or password spraying across multiple accounts (triage within 1h).\n• Critical: Active multi-hop lateral movement to database tiers, confirmed compromised credentials, or high-volume data exfiltration (immediate containment required).',
  },
  {
    q: 'How does the partial index on alerts optimize analyst queue filtering?',
    a: 'Analysts predominantly query active alerts needing investigation. SentinelDB creates a partial index on `alerts` with `partialFilterExpression: {"status": "open"}`. This keeps the index size tiny because resolved, acknowledged, and escalated historical alerts are excluded from the index b-tree, ensuring fast queue retrieval regardless of historical alert volume.',
  },
  {
    q: 'How are MITRE ATT&CK techniques mapped to SentinelDB detection rules?',
    a: 'Every detection pipeline and real-time rule is mapped to an industry-standard MITRE ATT&CK technique: T1110 (Brute Force), T1110.003 (Password Spraying), T1046 (Network Service Discovery / Port Scan), T1021 (Remote Services / Lateral Movement), and T1041 (Exfiltration Over C2 Channel). These IDs are embedded into alert documents and link directly to threat intelligence.',
  },
  {
    q: 'How does SentinelDB maintain data integrity with $jsonSchema validation?',
    a: 'Critical collections (`alerts`, `incidents`, `hosts`, `users`, `threat_intel`) enforce strict MongoDB `$jsonSchema` validators with `validationLevel: "strict"` and `validationAction: "error"`. This guarantees that malformed documents lacking required fields (such as MITRE taxonomy, timestamps, or IP addresses) are rejected at the database layer before ingestion.',
  },
];

export default function Help() {
  const [openIndex, setOpenIndex] = useState(0);

  const toggleAccordion = (idx) => {
    setOpenIndex(openIndex === idx ? null : idx);
  };

  return (
    <div style={{ maxWidth: '1000px', margin: '0 auto', padding: '24px 20px', minHeight: 'calc(100vh - 120px)' }}>
      {/* Title */}
      <div style={{ marginBottom: '28px' }}>
        <h1 style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
          Platform Knowledge Base & SOC FAQ
        </h1>
        <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '4px' }}>
          Comprehensive architectural guide to SentinelDB detection mechanics, MongoDB 7 query optimizations, and SOC triage workflows
        </p>
      </div>

      {/* Accordion container */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
        {FAQS.map((faq, idx) => {
          const isOpen = openIndex === idx;
          const headingId = `faq-head-${idx}`;
          const panelId = `faq-panel-${idx}`;

          return (
            <div
              key={idx}
              className="sdb-card"
              style={{
                overflow: 'hidden',
                borderColor: isOpen ? 'var(--accent-border)' : 'var(--border)',
                transition: 'border-color var(--transition-normal)',
              }}
            >
              <button
                type="button"
                id={headingId}
                aria-expanded={isOpen}
                aria-controls={panelId}
                onClick={() => toggleAccordion(idx)}
                style={{
                  width: '100%',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '16px 20px',
                  backgroundColor: isOpen ? 'var(--bg-surface-raised)' : 'var(--bg-surface)',
                  border: 'none',
                  color: 'var(--text-primary)',
                  fontSize: '14px',
                  fontWeight: 600,
                  textAlign: 'left',
                  cursor: 'pointer',
                  transition: 'background-color var(--transition-normal)',
                }}
                onMouseEnter={(e) => {
                  if (!isOpen) e.currentTarget.style.backgroundColor = 'var(--bg-surface-raised)';
                }}
                onMouseLeave={(e) => {
                  if (!isOpen) e.currentTarget.style.backgroundColor = 'var(--bg-surface)';
                }}
              >
                <span style={{ paddingRight: '16px' }}>{faq.q}</span>
                <span
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    width: '24px',
                    height: '24px',
                    borderRadius: '50%',
                    backgroundColor: isOpen ? 'var(--accent)' : 'var(--bg-muted)',
                    color: isOpen ? '#ffffff' : 'var(--text-secondary)',
                    transform: isOpen ? 'rotate(180deg)' : 'rotate(0deg)',
                    transition: 'all var(--transition-normal)',
                    flexShrink: 0,
                  }}
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                    <polyline points="6 9 12 15 18 9" />
                  </svg>
                </span>
              </button>

              {isOpen && (
                <div
                  id={panelId}
                  role="region"
                  aria-labelledby={headingId}
                  style={{
                    padding: '16px 20px',
                    fontSize: '13px',
                    lineHeight: 1.6,
                    color: 'var(--text-secondary)',
                    backgroundColor: 'var(--bg-surface)',
                    borderTop: '1px solid var(--border)',
                    whiteSpace: 'pre-line',
                  }}
                >
                  {faq.a}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
