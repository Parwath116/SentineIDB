import React, { useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { apiFetch } from '../api';
import { TableSkeleton } from '../components/Skeleton';
import PipelineViewer from '../components/PipelineViewer';

export default function LogSearch() {
  const [searchParams, setSearchParams] = useSearchParams();
  const searchInputRef = useRef(null);

  const [query, setQuery] = useState(searchParams.get('q') || 'rclone');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [pipelineMeta, setPipelineMeta] = useState(null);
  const [expandedLogId, setExpandedLogId] = useState(null);

  const executeSearch = async (term) => {
    if (!term || term.trim().length < 2) return;
    try {
      setLoading(true);
      setError(null);
      const res = await apiFetch(`/api/search?q=${encodeURIComponent(term)}&limit=50`);
      setResults(res.data || []);
      setPipelineMeta({ pipeline: res.pipeline, collection: res.collection });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const q = searchParams.get('q');
    if (q) {
      setQuery(q);
      executeSearch(q);
    } else {
      executeSearch(query);
    }
  }, [searchParams]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setSearchParams({ q: query });
  };

  const handleQuickChip = (term) => {
    setQuery(term);
    setSearchParams({ q: term });
  };

  return (
    <div style={{ maxWidth: '1440px', margin: '0 auto', padding: '24px 20px', minHeight: 'calc(100vh - 120px)' }}>
      {/* Title */}
      <div style={{ marginBottom: '20px' }}>
        <h1 style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
          Enterprise Log Search ($text)
        </h1>
        <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '2px' }}>
          Full-text index search on raw_logs ranked by textScore, joined with time-series telemetry events
        </p>
      </div>

      {/* Search Input Bar */}
      <div className="sdb-card" style={{ padding: '20px', marginBottom: '20px' }}>
        <form onSubmit={handleSearchSubmit} style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          <div style={{ position: 'relative', flex: 1 }}>
            <input
              ref={searchInputRef}
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search raw syslog messages, processes, or usernames (Press / to focus)..."
              style={{
                width: '100%',
                padding: '11px 40px 11px 14px',
                borderRadius: '6px',
                border: '1px solid var(--border)',
                backgroundColor: 'var(--bg-surface-raised)',
                color: 'var(--text-primary)',
                fontSize: '14px',
              }}
            />
            <span
              style={{
                position: 'absolute',
                right: '12px',
                top: '50%',
                transform: 'translateY(-50%)',
                fontFamily: 'var(--font-mono)',
                fontSize: '11px',
                color: 'var(--text-muted)',
                backgroundColor: 'var(--bg-surface)',
                border: '1px solid var(--border)',
                padding: '2px 6px',
                borderRadius: '4px',
                pointerEvents: 'none',
              }}
            >
              /
            </span>
          </div>

          <button
            type="submit"
            style={{
              padding: '11px 22px',
              borderRadius: '6px',
              border: 'none',
              backgroundColor: 'var(--accent)',
              color: '#ffffff',
              fontSize: '14px',
              fontWeight: 600,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
              <circle cx="11" cy="11" r="8" />
              <line x1="21" y1="21" x2="16.65" y2="16.65" />
            </svg>
            Search Logs
          </button>
        </form>

        {/* Quick Search Chips */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '12px', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600 }}>QUICK FILTERS:</span>
          {['rclone', 'psexec', 'powershell', '"Failed password"', 'DENY proto=TCP', '403'].map((chip) => (
            <button
              key={chip}
              type="button"
              onClick={() => handleQuickChip(chip)}
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '11px',
                padding: '3px 8px',
                borderRadius: '4px',
                border: '1px solid var(--border)',
                backgroundColor: 'var(--bg-surface-raised)',
                color: 'var(--text-secondary)',
                cursor: 'pointer',
              }}
            >
              {chip}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div role="alert" style={{ padding: '12px', borderRadius: '6px', backgroundColor: 'var(--danger-bg)', color: 'var(--danger)', marginBottom: '16px' }}>
          {error}
        </div>
      )}

      {/* Query Explorer */}
      {pipelineMeta && (
        <div style={{ marginBottom: '20px' }}>
          <PipelineViewer
            collection={pipelineMeta.collection}
            pipeline={pipelineMeta.pipeline}
            description="Pipeline 8 ($text + $lookup): executes index-backed full-text search on raw_logs, ranks documents by textScore, and performs a targeted $lookup to attach the time-series structured event."
          />
        </div>
      )}

      {/* Results Table */}
      {loading ? (
        <TableSkeleton rows={6} cols={5} />
      ) : results.length === 0 ? (
        <div className="sdb-card" style={{ padding: '48px', textAlign: 'center', color: 'var(--text-secondary)' }}>
          <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" style={{ color: 'var(--text-muted)', marginBottom: '8px' }}>
            <circle cx="11" cy="11" r="8" />
            <line x1="21" y1="21" x2="16.65" y2="16.65" />
          </svg>
          <h3 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)' }}>
            No Matching Log Messages
          </h3>
          <p style={{ fontSize: '13px', marginTop: '4px' }}>
            Try adjusting your query term or use one of the predefined quick search chips above.
          </p>
        </div>
      ) : (
        <div className="sdb-card" style={{ overflow: 'hidden' }}>
          <div style={{ padding: '12px 18px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
              Found {results.length} ranked log messages
            </span>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
              Click any row to reveal the joined time-series structured telemetry
            </span>
          </div>

          <table className="sdb-table">
            <thead>
              <tr>
                <th style={{ width: '160px' }}>Timestamp</th>
                <th style={{ width: '130px' }}>Host</th>
                <th style={{ width: '120px' }}>Source IP</th>
                <th style={{ width: '90px' }}>Relevance</th>
                <th>Raw Syslog Message</th>
              </tr>
            </thead>
            <tbody>
              {results.map((log) => {
                const isExpanded = expandedLogId === log._id;
                return (
                  <React.Fragment key={log._id}>
                    <tr
                      onClick={() => setExpandedLogId(isExpanded ? null : log._id)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', whiteSpace: 'nowrap' }}>
                        {new Date(log.ts).toLocaleString()}
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--accent)' }}>
                        {log.host}
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                        {log.srcIp}
                      </td>
                      <td>
                        <span
                          style={{
                            fontFamily: 'var(--font-mono)',
                            fontSize: '11px',
                            fontWeight: 600,
                            padding: '1px 5px',
                            borderRadius: '3px',
                            backgroundColor: 'var(--accent-light)',
                            color: 'var(--accent)',
                          }}
                        >
                          {log.score?.toFixed(2) || '1.00'}
                        </span>
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-primary)' }}>
                        {log.message}
                      </td>
                    </tr>

                    {/* Joined event expansion row */}
                    {isExpanded && (
                      <tr>
                        <td colSpan={5} style={{ backgroundColor: 'var(--bg-surface-raised)', padding: '16px' }}>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                              <span style={{ fontWeight: 600, fontSize: '12px', color: 'var(--text-primary)' }}>
                                Joined Structured Event ($lookup from events time-series):
                              </span>
                              {log.event ? (
                                <span
                                  style={{
                                    fontSize: '10px',
                                    fontWeight: 700,
                                    textTransform: 'uppercase',
                                    padding: '2px 6px',
                                    borderRadius: '3px',
                                    backgroundColor: 'var(--success-bg)',
                                    color: 'var(--success)',
                                  }}
                                >
                                  MATCH FOUND
                                </span>
                              ) : (
                                <span
                                  style={{
                                    fontSize: '10px',
                                    fontWeight: 700,
                                    textTransform: 'uppercase',
                                    padding: '2px 6px',
                                    borderRadius: '3px',
                                    backgroundColor: 'var(--bg-muted)',
                                    color: 'var(--text-muted)',
                                  }}
                                >
                                  NO CORRESPONDING EVENT RECORD
                                </span>
                              )}
                            </div>

                            {log.event ? (
                              <pre className="code-block" style={{ maxHeight: '140px' }}>
                                <code>{JSON.stringify(log.event, null, 2)}</code>
                              </pre>
                            ) : (
                              <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                                This log line was captured by endpoint audit agents without a structured firewall/auth event.
                              </p>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
