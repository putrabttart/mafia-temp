"use client";

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';

const DEFAULT_DOMAIN = 'selebungms.my.id';
const AUTO_REFRESH_MS = 10000;

function randomAlias(length = 10) {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let out = '';
  for (let i = 0; i < length; i += 1) {
    out += chars[Math.floor(Math.random() * chars.length)];
  }
  return out;
}

function useBootstrap() {
  useEffect(() => {
    import('bootstrap/dist/js/bootstrap.bundle.min.js');
  }, []);
}

export default function HomePage() {
  useBootstrap();
  const initialAddress = useMemo(
    () => `${randomAlias()}@${DEFAULT_DOMAIN}`,
    []
  );
  const [address, setAddress] = useState(initialAddress);
  const [messages, setMessages] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [lastRefreshed, setLastRefreshed] = useState('');
  const [detail, setDetail] = useState(null);
  const [toast, setToast] = useState('');

  async function copyToClipboard(text) {
    try {
      // Method 1: Modern Clipboard API (desktop + some mobile browsers)
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
        setToast('✓ Copied to clipboard');
        return;
      }
    } catch (err) {
      console.log('Clipboard API failed, trying fallback');
    }

    // Method 2: Fallback for older/mobile browsers
    try {
      const textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.style.position = 'fixed';
      textarea.style.top = '0';
      textarea.style.left = '0';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();
      textarea.setSelectionRange(0, 99999); // For mobile
      const success = document.execCommand('copy');
      document.body.removeChild(textarea);
      if (success) {
        setToast('✓ Copied to clipboard');
      } else {
        setToast('✗ Copy failed');
      }
    } catch (err) {
      console.error('Copy failed:', err);
      setToast('✗ Copy failed');
    }
  }

  async function registerAlias(addr) {
    try {
      await fetch('/api/aliases', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ address: addr })
      });
    } catch (e) {
      console.error('Failed to register alias', e);
    }
  }

  async function refreshInbox(currentAddr = address) {
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`/api/messages?alias=${encodeURIComponent(currentAddr)}`);
      if (!res.ok) throw new Error('Failed to fetch messages');
      const data = await res.json();
      setMessages(data.messages || []);
      setLastRefreshed(new Date().toLocaleTimeString());
    } catch (err) {
      console.error(err);
      setError('Failed to refresh messages');
    } finally {
      setLoading(false);
    }
  }

  async function openMessage(id) {
    try {
      setDetail({ loading: true });
      const res = await fetch(`/api/messages/${id}`);
      if (!res.ok) throw new Error('Failed to fetch message detail');
      const data = await res.json();
      setDetail({ ...data, loading: false });
    } catch (err) {
      console.error(err);
      setDetail({ loading: false, error: 'Failed to load message content' });
    }
  }

  useEffect(() => {
    registerAlias(address);
    refreshInbox(address);
    const timer = setInterval(() => refreshInbox(address), AUTO_REFRESH_MS);
    return () => clearInterval(timer);
  }, [address]);

  useEffect(() => {
    if (!toast) return undefined;
    const timer = setTimeout(() => setToast(''), 1800);
    return () => clearTimeout(timer);
  }, [toast]);

  return (
    <main style={{ background: '#f8fafc', minHeight: '100vh' }}>
      {/* Header */}
      <header className="bg-white border-bottom sticky-top">
        <div className="container-xl py-3">
          <div className="d-flex align-items-center justify-content-between gap-3">
            <div className="d-flex align-items-center gap-2">
              <div className="bg-primary text-white d-flex align-items-center justify-content-center rounded" style={{ width: 40, height: 40 }}>
                <i className="bi bi-envelope-fill" />
              </div>
              <h1 className="h5 mb-0">Mafia Tempmail</h1>
            </div>
            <Link href="/admin" className="btn btn-sm btn-outline-secondary">
              <i className="bi bi-gear me-1" /> Admin
            </Link>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="container-xl py-5">
        <div className="row justify-content-center">
          <div className="col-12 col-lg-8">
            {/* Email Input Section */}
            <div className="bg-white rounded-lg shadow-sm p-4 mb-4">
              <h6 className="text-uppercase text-muted fw-bold mb-3" style={{ fontSize: '0.75rem', letterSpacing: '0.05em' }}>
                Temporary Email Address
              </h6>
              <div className="input-group input-group-lg mb-3">
                <span className="input-group-text bg-light border-0">
                  <i className="bi bi-at" />
                </span>
                <input
                  value={address}
                  onChange={(e) => setAddress(e.target.value)}
                  className="form-control border-0 fs-5"
                  placeholder="your-email@selebungms.my.id"
                  spellCheck="false"
                />
              </div>
              <div className="d-grid gap-2 d-sm-flex">
                <button
                  className="btn btn-primary flex-grow-1"
                  onClick={() => copyToClipboard(address)}
                >
                  <i className="bi bi-clipboard me-2" /> Copy
                </button>
                <button
                  className="btn btn-outline-primary flex-grow-1"
                  onClick={() => {
                    const current = address.trim();
                    let domain = DEFAULT_DOMAIN;
                    if (current.includes('@')) domain = current.split('@')[1] || domain;
                    const alias = randomAlias(10);
                    const fullAddr = `${alias}@${domain}`;
                    setAddress(fullAddr);
                    registerAlias(fullAddr);
                    setToast('✓ New address generated');
                  }}
                >
                  <i className="bi bi-arrow-repeat me-2" /> Generate New
                </button>
              </div>
            </div>

            {/* Inbox Section */}
            <div className="bg-white rounded-lg shadow-sm overflow-hidden">
              <div className="d-flex align-items-center justify-content-between p-4 border-bottom bg-light">
                <h6 className="mb-0 fw-bold">Inbox</h6>
                <div className="d-flex align-items-center gap-2">
                  <small className="text-muted">
                    {lastRefreshed && `Updated ${lastRefreshed}`}
                  </small>
                  <button
                    className="btn btn-sm btn-primary"
                    onClick={() => refreshInbox()}
                    disabled={loading}
                  >
                    <i className={`bi ${loading ? 'bi-hourglass-split' : 'bi-arrow-clockwise'}`} />
                  </button>
                </div>
              </div>

              {error && (
                <div className="alert alert-warning m-0 rounded-0 border-0 d-flex align-items-center gap-2">
                  <i className="bi bi-exclamation-triangle-fill" />
                  <span>Refresh jika email belum masuk</span>
                </div>
              )}

              <div style={{ minHeight: '200px' }}>
                {loading && (
                  <div className="p-5 text-center text-muted">
                    <div className="spinner-border spinner-border-sm mb-2" role="status">
                      <span className="visually-hidden">Loading...</span>
                    </div>
                    <p className="small">Loading messages...</p>
                  </div>
                )}
                {!loading && messages.length === 0 && (
                  <div className="p-5 text-center text-muted">
                    <i className="bi bi-inbox" style={{ fontSize: '2rem' }} />
                    <p className="mt-2 small">No messages yet</p>
                  </div>
                )}
                {!loading && messages.length > 0 && (
                  <div className="list-group list-group-flush">
                    {messages.map((msg) => (
                      <button
                        key={msg.id}
                        type="button"
                        className="list-group-item list-group-item-action border-0 border-bottom text-start p-3 hover-light"
                        onClick={() => openMessage(msg.id)}
                        style={{ transition: 'background-color 0.15s' }}
                      >
                        <div className="d-flex justify-content-between align-items-start gap-2 mb-1">
                          <h6 className="mb-0 fw-600" style={{ fontSize: '0.95rem' }}>
                            {msg.subject || '(no subject)'}
                          </h6>
                          <small className="text-muted text-nowrap">{msg.date}</small>
                        </div>
                        <p className="mb-0 text-muted small" style={{ lineHeight: 1.4 }}>
                          {msg.snippet || '(no preview)'}
                        </p>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Email Detail Modal */}
      {detail && (
        <div className="modal fade show d-block" style={{ background: 'rgba(0,0,0,0.5)' }} onClick={() => setDetail(null)}>
          <div className="modal-dialog modal-lg modal-dialog-scrollable" onClick={(e) => e.stopPropagation()}>
            <div className="modal-content">
              <div className="modal-header border-0 bg-light">
                <h5 className="modal-title">{detail.loading ? 'Loading...' : detail.subject || '(no subject)'}</h5>
                <button type="button" className="btn-close" onClick={() => setDetail(null)} />
              </div>
              <div className="modal-body">
                {detail.loading && (
                  <div className="text-center text-muted py-5">
                    <div className="spinner-border spinner-border-sm mb-2" role="status">
                      <span className="visually-hidden">Loading...</span>
                    </div>
                    <p className="small">Loading message...</p>
                  </div>
                )}
                {detail.error && (
                  <div className="alert alert-danger mb-0">{detail.error}</div>
                )}
                {!detail.loading && !detail.error && (
                  <>
                    <div className="bg-light p-3 rounded mb-3">
                      <small className="d-block text-muted mb-1">
                        <strong>From:</strong> {detail.from}
                      </small>
                      <small className="d-block text-muted">
                        <strong>Date:</strong> {detail.date}
                      </small>
                    </div>
                    <div className="email-body">
                      {detail.bodyHtml ? (
                        <div dangerouslySetInnerHTML={{ __html: detail.bodyHtml }} />
                      ) : detail.bodyText ? (
                        <pre style={{ fontSize: '0.875rem', whiteSpace: 'pre-wrap', wordWrap: 'break-word' }}>
                          {detail.bodyText}
                        </pre>
                      ) : (
                        <p className="text-muted small">No content</p>
                      )}
                    </div>
                  </>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Toast Notification */}
      {toast && (
        <div
          className="position-fixed bottom-0 start-50 translate-middle-x mb-3 px-3 py-2 bg-dark text-white rounded-pill"
          style={{ zIndex: 2000, fontSize: '0.875rem' }}
        >
          {toast}
        </div>
      )}
    </main>
  );
}
