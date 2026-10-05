import React from 'react';

export function CardSkeleton() {
  return (
    <div className="sdb-card" style={{ padding: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '12px' }}>
        <div className="sdb-skeleton" style={{ width: '40%', height: '14px' }} />
        <div className="sdb-skeleton" style={{ width: '24px', height: '24px', borderRadius: '4px' }} />
      </div>
      <div className="sdb-skeleton" style={{ width: '60%', height: '28px', marginBottom: '8px' }} />
      <div className="sdb-skeleton" style={{ width: '80%', height: '12px' }} />
    </div>
  );
}

export function ChartSkeleton({ height = '260px' }) {
  return (
    <div className="sdb-card" style={{ padding: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '16px' }}>
        <div className="sdb-skeleton" style={{ width: '35%', height: '18px' }} />
        <div className="sdb-skeleton" style={{ width: '80px', height: '18px' }} />
      </div>
      <div className="sdb-skeleton" style={{ width: '100%', height }} />
    </div>
  );
}

export function TableSkeleton({ rows = 5, cols = 4 }) {
  return (
    <div className="sdb-card" style={{ overflow: 'hidden' }}>
      <div style={{ padding: '16px', borderBottom: '1px solid var(--border)' }}>
        <div className="sdb-skeleton" style={{ width: '25%', height: '18px' }} />
      </div>
      <div style={{ padding: '12px 16px' }}>
        <div style={{ display: 'flex', gap: '16px', marginBottom: '16px' }}>
          {Array.from({ length: cols }).map((_, i) => (
            <div key={i} className="sdb-skeleton" style={{ flex: 1, height: '14px' }} />
          ))}
        </div>
        {Array.from({ length: rows }).map((_, r) => (
          <div key={r} style={{ display: 'flex', gap: '16px', marginBottom: '12px' }}>
            {Array.from({ length: cols }).map((_, c) => (
              <div key={c} className="sdb-skeleton" style={{ flex: 1, height: '14px', opacity: 0.8 }} />
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}

export function FeedSkeleton({ count = 4 }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="sdb-card" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
            <div style={{ display: 'flex', gap: '8px', width: '50%' }}>
              <div className="sdb-skeleton" style={{ width: '70px', height: '20px', borderRadius: '12px' }} />
              <div className="sdb-skeleton" style={{ width: '80px', height: '20px', borderRadius: '12px' }} />
            </div>
            <div className="sdb-skeleton" style={{ width: '120px', height: '14px' }} />
          </div>
          <div className="sdb-skeleton" style={{ width: '70%', height: '18px', marginBottom: '8px' }} />
          <div className="sdb-skeleton" style={{ width: '45%', height: '12px' }} />
        </div>
      ))}
    </div>
  );
}

export function GraphSkeleton() {
  return (
    <div className="sdb-card" style={{ height: '540px', position: 'relative', overflow: 'hidden', padding: '24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '16px' }}>
        <div className="sdb-skeleton" style={{ width: '220px', height: '20px' }} />
        <div className="sdb-skeleton" style={{ width: '140px', height: '20px' }} />
      </div>
      <div
        className="sdb-skeleton"
        style={{
          width: '100%',
          height: '440px',
          borderRadius: '8px',
          opacity: 0.6,
        }}
      />
    </div>
  );
}
