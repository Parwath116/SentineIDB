import React, { useState } from 'react';

export default function PipelineViewer({ title = 'MongoDB Pipeline', collection, pipeline, description }) {
  const [isOpen, setIsOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  if (!pipeline) return null;

  const jsonString = typeof pipeline === 'string' ? pipeline : JSON.stringify(pipeline, null, 2);

  // Extract stage names for summary pills
  const stages = Array.isArray(pipeline)
    ? pipeline.map((stg) => Object.keys(stg)[0]).filter(Boolean)
    : [];

  const handleCopy = (e) => {
    e.stopPropagation();
    navigator.clipboard.writeText(jsonString);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div
      style={{
        marginTop: '12px',
        border: '1px solid var(--border)',
        borderRadius: '6px',
        backgroundColor: 'var(--bg-surface-raised)',
        overflow: 'hidden',
        fontSize: '13px',
      }}
    >
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        aria-expanded={isOpen}
        style={{
          width: '100%',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '8px 12px',
          background: 'none',
          border: 'none',
          cursor: 'pointer',
          color: 'var(--text-secondary)',
          fontWeight: 500,
          textAlign: 'left',
          transition: 'background-color var(--transition-normal)',
        }}
        onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'var(--bg-muted)')}
        onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: 'var(--accent)', fontWeight: 600 }}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
              <polyline points="16 18 22 12 16 6" />
              <polyline points="8 6 2 12 8 18" />
            </svg>
            View MongoDB pipeline
          </span>

          {collection && (
            <span
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '11px',
                padding: '2px 6px',
                borderRadius: '4px',
                backgroundColor: 'var(--bg-surface)',
                border: '1px solid var(--border)',
                color: 'var(--text-primary)',
              }}
            >
              db.{collection}
            </span>
          )}

          {stages.length > 0 && (
            <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
              {stages.slice(0, 5).map((stg, idx) => (
                <span
                  key={idx}
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: '10px',
                    padding: '1px 5px',
                    borderRadius: '3px',
                    backgroundColor: 'var(--accent-light)',
                    color: 'var(--accent)',
                  }}
                >
                  {stg}
                </span>
              ))}
              {stages.length > 5 && (
                <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>+{stages.length - 5} more</span>
              )}
            </div>
          )}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <svg
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            style={{
              transform: isOpen ? 'rotate(180deg)' : 'rotate(0deg)',
              transition: 'transform var(--transition-normal)',
            }}
          >
            <polyline points="6 9 12 15 18 9" />
          </svg>
        </div>
      </button>

      {isOpen && (
        <div style={{ padding: '12px', borderTop: '1px solid var(--border)', backgroundColor: 'var(--bg-surface)' }}>
          {description && (
            <p style={{ marginBottom: '8px', fontSize: '12px', color: 'var(--text-secondary)' }}>
              {description}
            </p>
          )}
          <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '6px' }}>
            <button
              type="button"
              onClick={handleCopy}
              style={{
                fontSize: '11px',
                padding: '3px 8px',
                borderRadius: '4px',
                border: '1px solid var(--border)',
                backgroundColor: 'var(--bg-surface-raised)',
                color: 'var(--text-secondary)',
                cursor: 'pointer',
              }}
            >
              {copied ? 'Copied Pipeline!' : 'Copy Aggregation JSON'}
            </button>
          </div>
          <pre className="code-block" style={{ maxHeight: '280px', overflowY: 'auto' }}>
            <code>{jsonString}</code>
          </pre>
        </div>
      )}
    </div>
  );
}
