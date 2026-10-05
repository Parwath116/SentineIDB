import React from 'react';

/**
 * React Error Boundary that catches JavaScript errors anywhere in its child component tree,
 * logs those errors, and displays a graceful fallback UI with a retry button instead of a blank screen.
 */
export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error(`[ErrorBoundary] Uncaught error in ${this.props.pageName || 'component'}:`, error, errorInfo);
    this.setState({ errorInfo });
  }

  handleRetry = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
    if (this.props.onRetry) {
      this.props.onRetry();
    }
  };

  handleReload = () => {
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      const pageTitle = this.props.pageName || 'Component';
      const errorMessage = this.state.error?.message || String(this.state.error || 'Unknown error');

      return (
        <div
          role="alert"
          style={{
            maxWidth: '800px',
            margin: '40px auto',
            padding: '32px',
            backgroundColor: 'var(--bg-surface-raised)',
            border: '1px solid var(--border)',
            borderRadius: '10px',
            boxShadow: 'var(--shadow-md)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
            <div
              style={{
                width: '36px',
                height: '36px',
                borderRadius: '8px',
                backgroundColor: 'var(--critical-bg)',
                color: 'var(--critical)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontWeight: 700,
                fontSize: '18px',
              }}
            >
              ⚠
            </div>
            <div>
              <h2 style={{ fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                {pageTitle} Failed to Render
              </h2>
              <p style={{ fontSize: '13px', color: 'var(--text-secondary)', margin: '4px 0 0 0' }}>
                An unexpected exception occurred while loading this view. The rest of the application remains operational.
              </p>
            </div>
          </div>

          <div
            style={{
              padding: '14px 16px',
              borderRadius: '6px',
              backgroundColor: 'var(--bg-primary)',
              border: '1px solid var(--border)',
              fontFamily: 'var(--font-mono)',
              fontSize: '12px',
              color: 'var(--danger)',
              overflowX: 'auto',
              marginBottom: '24px',
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-word',
            }}
          >
            {errorMessage}
          </div>

          <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
            <button
              onClick={this.handleRetry}
              className="sdb-btn"
              style={{
                padding: '9px 18px',
                backgroundColor: 'var(--accent)',
                color: '#ffffff',
                fontWeight: 600,
                fontSize: '13px',
                borderRadius: '6px',
                border: 'none',
                cursor: 'pointer',
              }}
            >
              Retry View
            </button>

            <button
              onClick={this.handleReload}
              className="sdb-btn"
              style={{
                padding: '9px 18px',
                backgroundColor: 'var(--bg-surface-raised)',
                color: 'var(--text-primary)',
                fontWeight: 500,
                fontSize: '13px',
                borderRadius: '6px',
                border: '1px solid var(--border)',
                cursor: 'pointer',
              }}
            >
              Reload Page
            </button>

            <a
              href="/"
              className="sdb-btn"
              style={{
                padding: '9px 18px',
                backgroundColor: 'transparent',
                color: 'var(--text-secondary)',
                fontWeight: 500,
                fontSize: '13px',
                borderRadius: '6px',
                border: '1px solid var(--border)',
                textDecoration: 'none',
                display: 'inline-flex',
                alignItems: 'center',
              }}
            >
              Return to Dashboard
            </a>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
