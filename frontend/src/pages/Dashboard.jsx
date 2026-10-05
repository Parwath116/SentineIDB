import React, { useEffect, useState } from 'react';
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  BarChart, Bar, PieChart, Pie, Cell, Legend
} from 'recharts';
import { apiFetch } from '../api';
import { useTheme } from '../context/ThemeContext';
import { CardSkeleton, ChartSkeleton } from '../components/Skeleton';
import PipelineViewer from '../components/PipelineViewer';

export default function Dashboard() {
  const { theme } = useTheme();
  const [loading, setLoading] = useState(true);
  const [kpis, setKpis] = useState(null);
  const [attacksPerHour, setAttacksPerHour] = useState(null);
  const [facets, setFacets] = useState(null);
  const [severityData, setSeverityData] = useState(null);
  const [error, setError] = useState(null);

  const isDark = theme === 'dark';
  const axisColor = isDark ? '#64748b' : '#94a3b8';
  const gridColor = isDark ? '#1e293b' : '#f1f5f9';
  const tooltipBg = isDark ? '#1e293b' : '#ffffff';
  const tooltipBorder = isDark ? '#334155' : '#e2e8f0';
  const tooltipColor = isDark ? '#f8fafc' : '#0f172a';

  useEffect(() => {
    async function loadDashboard() {
      try {
        setLoading(true);
        const [kpiRes, aphRes, facetRes, sevRes] = await Promise.all([
          apiFetch('/api/dashboard/kpis'),
          apiFetch('/api/dashboard/attacks-per-hour?days=7'),
          apiFetch('/api/dashboard/facets?days=7'),
          apiFetch('/api/dashboard/alert-severity'),
        ]);
        setKpis(kpiRes);
        setAttacksPerHour(aphRes);
        setFacets(facetRes);
        setSeverityData(sevRes);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }
    loadDashboard();
  }, []);

  const SEVERITY_COLORS = {
    critical: '#a855f7',
    high: '#ef4444',
    medium: '#f59e0b',
    low: '#38bdf8',
    info: '#64748b',
  };

  // Format hours for XAxis
  const formattedHourly = (attacksPerHour?.data || []).map((d) => ({
    ...d,
    timeLabel: new Date(d.hour).toLocaleDateString([], { month: 'short', day: 'numeric', hour: '2-digit' }),
  }));

  const pieData = (severityData?.data || []).map((d) => ({
    name: d._id.toUpperCase(),
    value: d.alerts,
    color: SEVERITY_COLORS[d._id.toLowerCase()] || '#94a3b8',
  }));

  const timeOfDayData = (facets?.data?.timeOfDay || []).map((d) => {
    const labels = {
      0: 'Night (00-06)',
      6: 'Morning (06-12)',
      12: 'Afternoon (12-18)',
      18: 'Evening (18-24)',
    };
    return {
      bucket: labels[d._id] || `Hour ${d._id}`,
      events: d.events,
    };
  });

  return (
    <div style={{ maxWidth: '1440px', margin: '0 auto', padding: '24px 20px', minHeight: 'calc(100vh - 120px)' }}>
      {/* Title banner */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h1 style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
            SOC Operations Dashboard
          </h1>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '2px' }}>
            Real-time threat telemetry, attack velocity, and security KPIs for Northwind Logistics
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '4px 10px',
              borderRadius: '12px',
              backgroundColor: 'var(--success-bg)',
              color: 'var(--success)',
              border: '1px solid var(--success-border)',
              fontSize: '12px',
              fontWeight: 600,
            }}
          >
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: 'var(--success)', display: 'inline-block' }} />
            Ingestion Live (rs0 primary)
          </span>
        </div>
      </div>

      {error && (
        <div
          role="alert"
          style={{
            padding: '14px',
            borderRadius: '8px',
            backgroundColor: 'var(--danger-bg)',
            border: '1px solid var(--danger-border)',
            color: 'var(--danger)',
            marginBottom: '24px',
          }}
        >
          {error}
        </div>
      )}

      {/* KPI Cards Row */}
      {loading ? (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px', marginBottom: '24px' }}>
          <CardSkeleton />
          <CardSkeleton />
          <CardSkeleton />
          <CardSkeleton />
          <CardSkeleton />
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px', marginBottom: '24px' }}>
          {/* Card 1 */}
          <div className="sdb-card sdb-card-hover" style={{ padding: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-secondary)', fontSize: '12px', fontWeight: 600 }}>
              <span>TOTAL EVENTS (24H)</span>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10" />
                <polyline points="12 6 12 12 14 14" />
              </svg>
            </div>
            <div style={{ fontSize: '26px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '8px' }}>
              {(kpis?.data?.events || 0).toLocaleString()}
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
              Aggregated from hourly_summary ($merge)
            </div>
          </div>

          {/* Card 2 */}
          <div className="sdb-card sdb-card-hover" style={{ padding: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--danger)', fontSize: '12px', fontWeight: 600 }}>
              <span>SUSPICIOUS EVENTS</span>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
                <line x1="12" y1="9" x2="12" y2="13" />
                <line x1="12" y1="17" x2="12.01" y2="17" />
              </svg>
            </div>
            <div style={{ fontSize: '26px', fontWeight: 700, color: 'var(--danger)', marginTop: '8px' }}>
              {(kpis?.data?.suspicious || 0).toLocaleString()}
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
              auth_fail + fw_deny in last 24h
            </div>
          </div>

          {/* Card 3 */}
          <div className="sdb-card sdb-card-hover" style={{ padding: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--warning)', fontSize: '12px', fontWeight: 600 }}>
              <span>ACTIVE ALERTS</span>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
                <path d="M13.73 21a2 2 0 0 1-3.46 0" />
              </svg>
            </div>
            <div style={{ fontSize: '26px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '8px' }}>
              {kpis?.data?.openAlerts || 0}
            </div>
            <div style={{ fontSize: '12px', color: 'var(--critical)', marginTop: '4px', fontWeight: 600 }}>
              {kpis?.data?.criticalAlerts || 0} Critical priority
            </div>
          </div>

          {/* Card 4 */}
          <div className="sdb-card sdb-card-hover" style={{ padding: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--critical)', fontSize: '12px', fontWeight: 600 }}>
              <span>HIGH-RISK ENTITIES</span>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
                <circle cx="9" cy="7" r="4" />
                <path d="M22 21v-2a4 4 0 0 0-3-3.87" />
                <path d="M16 3.13a4 4 0 0 1 0 7.75" />
              </svg>
            </div>
            <div style={{ fontSize: '26px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '8px' }}>
              {kpis?.data?.highRiskIps || 0}
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
              Source IPs with riskScore &ge; 50
            </div>
          </div>

          {/* Card 5 */}
          <div className="sdb-card sdb-card-hover" style={{ padding: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--info)', fontSize: '12px', fontWeight: 600 }}>
              <span>DATA OUTBOUND</span>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                <polyline points="17 8 12 3 7 8" />
                <line x1="12" y1="3" x2="12" y2="15" />
              </svg>
            </div>
            <div style={{ fontSize: '26px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '8px' }}>
              {((kpis?.data?.bytesOut || 0) / 1e9).toFixed(2)} GB
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
              Total payload transferred in 24h
            </div>
          </div>
        </div>
      )}

      {/* Pipeline for KPIs */}
      {!loading && kpis?.pipeline && (
        <div style={{ marginBottom: '24px' }}>
          <PipelineViewer
            title="KPI Aggregation ($merge readout)"
            collection="hourly_summary"
            pipeline={kpis.pipeline}
            description="Reads pre-computed 24h totals from the materialized hourly_summary collection (Pipeline 9)."
          />
        </div>
      )}

      {/* Main Chart: Attacks per Hour */}
      <div className="sdb-card" style={{ padding: '20px', marginBottom: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <div>
            <h2 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)' }}>
              Attack & Suspicious Velocity Over Time (7-Day Horizon)
            </h2>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
              Hourly volume of authentication failures and firewall drops pre-aggregated in hourly_summary
            </p>
          </div>
        </div>

        {loading ? (
          <ChartSkeleton height="280px" />
        ) : (
          <div style={{ width: '100%', height: '280px' }}>
            <ResponsiveContainer>
              <AreaChart data={formattedHourly}>
                <defs>
                  <linearGradient id="suspiciousGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="timeLabel" stroke={axisColor} fontSize={11} tickLine={false} />
                <YAxis stroke={axisColor} fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: tooltipBg,
                    borderColor: tooltipBorder,
                    color: tooltipColor,
                    borderRadius: '6px',
                    fontSize: '12px',
                  }}
                />
                <Area type="monotone" dataKey="suspicious" name="Suspicious Events" stroke="#ef4444" strokeWidth={2} fillOpacity={1} fill="url(#suspiciousGrad)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}

        <PipelineViewer
          collection={attacksPerHour?.collection}
          pipeline={attacksPerHour?.pipeline}
          description="Pipeline 9 Readout: queries precomputed hourly buckets by indexed 'hour' timestamp."
        />
      </div>

      {/* Grid: Top Attackers & Severity Breakdown */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(440px, 1fr))', gap: '24px', marginBottom: '24px' }}>
        {/* Top Attackers Chart */}
        <div className="sdb-card" style={{ padding: '20px' }}>
          <h2 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '4px' }}>
            Top Threat Actors by Activity Volume
          </h2>
          <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
            Evaluated with $facet across malicious telemetry
          </p>

          {loading ? (
            <ChartSkeleton height="240px" />
          ) : (
            <div style={{ width: '100%', height: '240px' }}>
              <ResponsiveContainer>
                <BarChart data={facets?.data?.topAttackers || []} layout="vertical">
                  <XAxis type="number" stroke={axisColor} fontSize={11} />
                  <YAxis type="category" dataKey="_id" stroke={axisColor} fontSize={11} width={100} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: tooltipBg,
                      borderColor: tooltipBorder,
                      color: tooltipColor,
                      borderRadius: '6px',
                      fontSize: '12px',
                    }}
                  />
                  <Bar dataKey="events" name="Total Events" fill="#3b82f6" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}

          <PipelineViewer
            collection={facets?.collection}
            pipeline={facets?.pipeline}
            description="Pipeline 7 ($facet): computes top attackers, targeted hosts, severity breakdown, and time-of-day buckets in a single pass over events."
          />
        </div>

        {/* Severity Breakdown */}
        <div className="sdb-card" style={{ padding: '20px' }}>
          <h2 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '4px' }}>
            Alert Severity Breakdown
          </h2>
          <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
            Distribution of open alerts across response tiers
          </p>

          {loading ? (
            <ChartSkeleton height="240px" />
          ) : (
            <div style={{ width: '100%', height: '240px' }}>
              <ResponsiveContainer>
                <PieChart>
                  <Pie
                    data={pieData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={85}
                    paddingAngle={3}
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: tooltipBg,
                      borderColor: tooltipBorder,
                      color: tooltipColor,
                      borderRadius: '6px',
                      fontSize: '12px',
                    }}
                  />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}

          <PipelineViewer
            collection={severityData?.collection}
            pipeline={severityData?.pipeline}
            description="Groups active alerts by severity level to determine SOC triage distribution."
          />
        </div>
      </div>

      {/* Secondary Grid: Targeted Hosts & Time of Day */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(440px, 1fr))', gap: '24px' }}>
        {/* Targeted Hosts Table */}
        <div className="sdb-card" style={{ padding: '20px' }}>
          <h2 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '4px' }}>
            Most Targeted Infrastructure Hosts
          </h2>
          <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
            Perimeter and server endpoints absorbing highest threat volume
          </p>

          {loading ? (
            <ChartSkeleton height="180px" />
          ) : (
            <table className="sdb-table">
              <thead>
                <tr>
                  <th>Hostname</th>
                  <th>Incident / Event Hits</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {(facets?.data?.targetedHosts || []).slice(0, 5).map((h) => (
                  <tr key={h._id}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--accent)' }}>
                      {h._id}
                    </td>
                    <td>{h.events.toLocaleString()}</td>
                    <td>
                      <a href={`/search?q=${h._id}`} style={{ fontSize: '12px' }}>
                        Investigate logs &rarr;
                      </a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Time of Day ($bucket) */}
        <div className="sdb-card" style={{ padding: '20px' }}>
          <h2 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '4px' }}>
            Threat Velocity by Time of Day ($bucket)
          </h2>
          <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
            MongoDB $bucket stage grouping attacks into 6-hour enterprise operational windows
          </p>

          {loading ? (
            <ChartSkeleton height="180px" />
          ) : (
            <div style={{ width: '100%', height: '180px' }}>
              <ResponsiveContainer>
                <BarChart data={timeOfDayData}>
                  <XAxis dataKey="bucket" stroke={axisColor} fontSize={11} />
                  <YAxis stroke={axisColor} fontSize={11} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: tooltipBg,
                      borderColor: tooltipBorder,
                      color: tooltipColor,
                      borderRadius: '6px',
                      fontSize: '12px',
                    }}
                  />
                  <Bar dataKey="events" name="Attacks" fill="#6366f1" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
