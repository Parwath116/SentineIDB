import React, { useEffect, useState } from 'react';
import { apiFetch } from '../api';
import { useAuth } from '../context/AuthContext';
import { FeedSkeleton } from '../components/Skeleton';
import PipelineViewer from '../components/PipelineViewer';

export default function Alerts() {
  const { user, token } = useAuth();
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');
  const [streamConnected, setStreamConnected] = useState(false);
  const [streamCounts, setStreamCounts] = useState(null);
  const [error, setError] = useState(null);
  const [pipelineMeta, setPipelineMeta] = useState(null);

  // Escalate modal state
  const [escalatingAlert, setEscalatingAlert] = useState(null);
  const [incidentTitle, setIncidentTitle] = useState('');
  const [incidentNotes, setIncidentNotes] = useState('');
  const [isEscalating, setIsEscalating] = useState(false);

  // Expanded evidence drawer for alerts
  const [expandedAlertId, setExpandedAlertId] = useState(null);

  // Initial load
  const loadAlerts = async () => {
    try {
      setLoading(true);
      let query = '/api/alerts?limit=100';
      if (filterStatus !== 'all') query += `&status=${filterStatus}`;
      if (filterSeverity !== 'all') query += `&severity=${filterSeverity}`;
      const res = await apiFetch(query);
      setAlerts(res.data || []);
      setPipelineMeta({ pipeline: res.pipeline, collection: res.collection });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAlerts();
  }, [filterStatus, filterSeverity]);

  // Server-Sent Events stream for live alerts
  useEffect(() => {
    if (!token) return;
    const es = new EventSource(`/api/stream?token=${encodeURIComponent(token)}`);

    es.onopen = () => {
      setStreamConnected(true);
    };

    es.addEventListener('counts', (e) => {
      try {
        setStreamCounts(JSON.parse(e.data));
      } catch {}
    });

    es.addEventListener('alert', (e) => {
      try {
        const newAlert = JSON.parse(e.data);
        setAlerts((prev) => {
          // If already in list, update; otherwise prepend
          const exists = prev.some((a) => a._id === newAlert._id);
          if (exists) {
            return prev.map((a) => (a._id === newAlert._id ? newAlert : a));
          }
          return [newAlert, ...prev];
        });
      } catch {}
    });

    es.onerror = () => {
      setStreamConnected(false);
    };

    return () => {
      es.close();
    };
  }, [token]);

  const handleAcknowledge = async (alertId) => {
    try {
      await apiFetch(`/api/alerts/${alertId}/acknowledge`, { method: 'POST' });
      setAlerts((prev) =>
        prev.map((a) =>
          a._id === alertId ? { ...a, status: 'acknowledged', acknowledgedBy: user.username } : a
        )
      );
    } catch (err) {
      alert(`Could not acknowledge alert: ${err.message}`);
    }
  };

  const handleOpenEscalateModal = (alert) => {
    setEscalatingAlert(alert);
    setIncidentTitle(`Investigate ${alert.type} from ${alert.srcIp}`);
    setIncidentNotes(`Initial triage by ${user.username}. Triggered by rule: ${alert.evidence?.rule || alert.type}.`);
  };

  const handleConfirmEscalate = async (e) => {
    e.preventDefault();
    if (!escalatingAlert) return;
    try {
      setIsEscalating(true);
      const res = await apiFetch(`/api/alerts/${escalatingAlert._id}/escalate`, {
        method: 'POST',
        body: JSON.stringify({ title: incidentTitle, notes: incidentNotes }),
      });
      setAlerts((prev) =>
        prev.map((a) =>
          a._id === escalatingAlert._id
            ? { ...a, status: 'escalated', incidentId: res.incidentId, acknowledgedBy: user.username }
            : a
        )
      );
      setEscalatingAlert(null);
    } catch (err) {
      alert(`Failed to escalate incident: ${err.message}`);
    } finally {
      setIsEscalating(false);
    }
  };

  return (
    <div style={{ maxWidth: '1440px', margin: '0 auto', padding: '24px 20px', minHeight: 'calc(100vh - 120px)' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h1 style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
            Live Security Alerts Feed
          </h1>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '2px' }}>
            Real-time change stream evaluations on ip_state with MITRE ATT&CK technique tags
          </p>
        </div>

        {/* Live SSE Indicator */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '6px 12px',
              borderRadius: '20px',
              backgroundColor: streamConnected ? 'var(--success-bg)' : 'var(--danger-bg)',
              color: streamConnected ? 'var(--success)' : 'var(--danger)',
              border: `1px solid ${streamConnected ? 'var(--success-border)' : 'var(--danger-border)'}`,
              fontSize: '12px',
              fontWeight: 600,
            }}
          >
            <span
              style={{
                width: '8px',
                height: '8px',
                borderRadius: '50%',
                backgroundColor: streamConnected ? 'var(--success)' : 'var(--danger)',
                display: 'inline-block',
                animation: streamConnected ? 'pulse 2s infinite' : 'none',
              }}
            />
            {streamConnected ? 'SSE Connected (Real-Time)' : 'Connecting to Stream...'}
          </div>

          {streamCounts && (
            <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
              Velocity: <strong>{streamCounts.eventsLastMinute}</strong> ev/min
            </span>
          )}
        </div>
      </div>

      {error && (
        <div role="alert" style={{ padding: '12px', borderRadius: '6px', backgroundColor: 'var(--danger-bg)', color: 'var(--danger)', marginBottom: '16px' }}>
          {error}
        </div>
      )}

      {/* Filter controls */}
      <div
        className="sdb-card"
        style={{
          padding: '14px 18px',
          marginBottom: '20px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '12px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
          <div>
            <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', marginRight: '6px' }}>
              Status:
            </label>
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              style={{
                padding: '5px 10px',
                borderRadius: '5px',
                border: '1px solid var(--border)',
                backgroundColor: 'var(--bg-surface-raised)',
                color: 'var(--text-primary)',
                fontSize: '12px',
              }}
            >
              <option value="all">All Statuses</option>
              <option value="open">Open (Partial Index)</option>
              <option value="acknowledged">Acknowledged</option>
              <option value="escalated">Escalated to Incident</option>
            </select>
          </div>

          <div>
            <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', marginRight: '6px' }}>
              Severity:
            </label>
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              style={{
                padding: '5px 10px',
                borderRadius: '5px',
                border: '1px solid var(--border)',
                backgroundColor: 'var(--bg-surface-raised)',
                color: 'var(--text-primary)',
                fontSize: '12px',
              }}
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
        </div>

        <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
          Showing <strong>{alerts.length}</strong> matching detection records
        </div>
      </div>

      {/* Query Explorer */}
      {pipelineMeta && (
        <div style={{ marginBottom: '20px' }}>
          <PipelineViewer
            collection={pipelineMeta.collection}
            pipeline={pipelineMeta.pipeline}
            description="Filters alerts by status and severity using the compound status_severity_ts index, or the partialFilterExpression index when status=open."
          />
        </div>
      )}

      {/* Alerts list */}
      {loading ? (
        <FeedSkeleton count={5} />
      ) : alerts.length === 0 ? (
        <div
          className="sdb-card"
          style={{
            padding: '48px',
            textAlign: 'center',
            color: 'var(--text-secondary)',
          }}
        >
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" style={{ color: 'var(--success)', marginBottom: '12px' }}>
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
            <polyline points="22 4 12 14.01 9 11.01" />
          </svg>
          <h3 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)' }}>
            No Active Alerts in this Queue
          </h3>
          <p style={{ fontSize: '13px', marginTop: '4px' }}>
            All matching alerts have been triaged or no events have breached detection thresholds.
          </p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {alerts.map((alert) => {
            const isExpanded = expandedAlertId === alert._id;
            return (
              <div
                key={alert._id}
                className="sdb-card sdb-card-hover"
                style={{
                  padding: '16px 20px',
                  borderLeft: `4px solid var(--${alert.severity === 'critical' ? 'critical' : alert.severity === 'high' ? 'danger' : alert.severity === 'medium' ? 'warning' : 'info'})`,
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '10px' }}>
                  {/* Left: Badges & Title */}
                  <div style={{ flex: 1, minWidth: '280px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px', flexWrap: 'wrap' }}>
                      {/* Severity badge */}
                      <span
                        className={`badge-${alert.severity}`}
                        style={{
                          fontSize: '11px',
                          fontWeight: 700,
                          textTransform: 'uppercase',
                          padding: '2px 8px',
                          borderRadius: '12px',
                        }}
                      >
                        {alert.severity}
                      </span>

                      {/* Status badge */}
                      <span
                        style={{
                          fontSize: '11px',
                          fontWeight: 600,
                          textTransform: 'capitalize',
                          padding: '2px 8px',
                          borderRadius: '12px',
                          backgroundColor:
                            alert.status === 'open'
                              ? 'var(--warning-bg)'
                              : alert.status === 'acknowledged'
                              ? 'var(--info-bg)'
                              : 'var(--critical-bg)',
                          color:
                            alert.status === 'open'
                              ? 'var(--warning)'
                              : alert.status === 'acknowledged'
                              ? 'var(--info)'
                              : 'var(--critical)',
                          border: '1px solid var(--border)',
                        }}
                      >
                        {alert.status}
                      </span>

                      {/* MITRE Badge */}
                      {alert.mitre && (
                        <span
                          title={`${alert.mitre.name} (${alert.mitre.tactic})`}
                          style={{
                            fontFamily: 'var(--font-mono)',
                            fontSize: '11px',
                            fontWeight: 600,
                            padding: '2px 8px',
                            borderRadius: '4px',
                            backgroundColor: 'var(--bg-surface-raised)',
                            border: '1px solid var(--border)',
                            color: 'var(--text-primary)',
                          }}
                        >
                          MITRE {alert.mitre.id}: {alert.mitre.name}
                        </span>
                      )}

                      {/* Threat Intel Tag */}
                      {alert.evidence?.threatIntel && (
                        <span
                          style={{
                            fontSize: '11px',
                            fontWeight: 600,
                            padding: '2px 8px',
                            borderRadius: '4px',
                            backgroundColor: 'var(--danger-bg)',
                            color: 'var(--danger)',
                            border: '1px solid var(--danger-border)',
                          }}
                        >
                          Threat Intel: {alert.evidence.threatIntel.category} (Confidence: {alert.evidence.threatIntel.confidence}%)
                        </span>
                      )}
                    </div>

                    <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '4px' }}>
                      {alert.type}
                    </h3>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '16px', fontSize: '12px', color: 'var(--text-secondary)', flexWrap: 'wrap' }}>
                      <span>
                        Source IP: <strong style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>{alert.srcIp}</strong>
                      </span>
                      {alert.targetHost && (
                        <span>
                          Target: <strong style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>{alert.targetHost}</strong>
                        </span>
                      )}
                      <span>
                        Detected: {new Date(alert.ts).toLocaleString()}
                      </span>
                      {alert.acknowledgedBy && (
                        <span>
                          Triaged by: <strong>{alert.acknowledgedBy}</strong>
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Right: Actions */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <button
                      type="button"
                      onClick={() => setExpandedAlertId(isExpanded ? null : alert._id)}
                      style={{
                        padding: '6px 12px',
                        fontSize: '12px',
                        borderRadius: '6px',
                        border: '1px solid var(--border)',
                        backgroundColor: 'var(--bg-surface-raised)',
                        color: 'var(--text-secondary)',
                        cursor: 'pointer',
                      }}
                    >
                      {isExpanded ? 'Hide Evidence' : 'View Evidence'}
                    </button>

                    {alert.status === 'open' && (
                      <button
                        type="button"
                        onClick={() => handleAcknowledge(alert._id)}
                        style={{
                          padding: '6px 12px',
                          fontSize: '12px',
                          fontWeight: 500,
                          borderRadius: '6px',
                          border: '1px solid var(--border)',
                          backgroundColor: 'var(--bg-surface)',
                          color: 'var(--text-primary)',
                          cursor: 'pointer',
                        }}
                      >
                        Acknowledge
                      </button>
                    )}

                    {alert.status !== 'escalated' && (
                      <button
                        type="button"
                        onClick={() => handleOpenEscalateModal(alert)}
                        style={{
                          padding: '6px 12px',
                          fontSize: '12px',
                          fontWeight: 500,
                          borderRadius: '6px',
                          border: 'none',
                          backgroundColor: 'var(--accent)',
                          color: '#ffffff',
                          cursor: 'pointer',
                        }}
                      >
                        Escalate to Incident
                      </button>
                    )}
                  </div>
                </div>

                {/* Evidence Drawer */}
                {isExpanded && (
                  <div
                    style={{
                      marginTop: '14px',
                      padding: '14px',
                      borderRadius: '6px',
                      backgroundColor: 'var(--bg-surface-raised)',
                      border: '1px solid var(--border)',
                      fontSize: '12px',
                    }}
                  >
                    <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '6px' }}>
                      Diagnostic Evidence & Threshold Match:
                    </div>
                    <pre className="code-block" style={{ maxHeight: '180px', overflowY: 'auto' }}>
                      <code>{JSON.stringify(alert.evidence, null, 2)}</code>
                    </pre>

                    <div style={{ marginTop: '10px', display: 'flex', gap: '12px' }}>
                      <a href={`/search?q=${alert.srcIp}`} style={{ fontSize: '12px' }}>
                        View raw logs for {alert.srcIp} &rarr;
                      </a>
                      {alert.targetHost && (
                        <a href={`/chains`} style={{ fontSize: '12px' }}>
                          Explore attack graph &rarr;
                        </a>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Escalate Modal */}
      {escalatingAlert && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="escalate-modal-title"
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            width: '100vw',
            height: '100vh',
            backgroundColor: 'rgba(0, 0, 0, 0.6)',
            backdropFilter: 'blur(3px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1100,
          }}
          onClick={(e) => {
            if (e.target === e.currentTarget) setEscalatingAlert(null);
          }}
        >
          <div
            className="sdb-card"
            style={{
              width: '520px',
              maxWidth: 'calc(100vw - 32px)',
              padding: '24px',
              boxShadow: 'var(--shadow-xl)',
            }}
          >
            <h2 id="escalate-modal-title" style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '6px' }}>
              Escalate Alert to Security Incident
            </h2>
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
              Creates an enterprise tracking incident in the validated incidents collection and links this alert.
            </p>

            <form onSubmit={handleConfirmEscalate} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '4px' }}>
                  Incident Title
                </label>
                <input
                  type="text"
                  required
                  value={incidentTitle}
                  onChange={(e) => setIncidentTitle(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    borderRadius: '6px',
                    border: '1px solid var(--border)',
                    backgroundColor: 'var(--bg-surface-raised)',
                    color: 'var(--text-primary)',
                    fontSize: '13px',
                  }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '4px' }}>
                  Triage Notes & Remediation Directives
                </label>
                <textarea
                  rows={4}
                  value={incidentNotes}
                  onChange={(e) => setIncidentNotes(e.target.value)}
                  placeholder="Enter initial containment guidance, affected assets, or analyst observations..."
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    borderRadius: '6px',
                    border: '1px solid var(--border)',
                    backgroundColor: 'var(--bg-surface-raised)',
                    color: 'var(--text-primary)',
                    fontSize: '13px',
                    resize: 'vertical',
                  }}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '10px' }}>
                <button
                  type="button"
                  onClick={() => setEscalatingAlert(null)}
                  style={{
                    padding: '8px 14px',
                    fontSize: '13px',
                    borderRadius: '6px',
                    border: '1px solid var(--border)',
                    backgroundColor: 'transparent',
                    color: 'var(--text-secondary)',
                    cursor: 'pointer',
                  }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isEscalating}
                  style={{
                    padding: '8px 18px',
                    fontSize: '13px',
                    fontWeight: 600,
                    borderRadius: '6px',
                    backgroundColor: 'var(--accent)',
                    border: 'none',
                    color: '#ffffff',
                    cursor: isEscalating ? 'not-allowed' : 'pointer',
                  }}
                >
                  {isEscalating ? 'Creating Incident...' : 'Confirm Escalation'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
