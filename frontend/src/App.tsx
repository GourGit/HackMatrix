import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Search, 
  AlertTriangle, 
  CheckCircle, 
  Lock, 
  Globe, 
  Server, 
  FileText, 
  ExternalLink,
  RefreshCw,
  Info
} from 'lucide-react';
import { createAssessment, getAssessment, getOrInitVisitorSession } from './api/client';
import { AssessmentDetail, Finding, CheckStatus } from './types';

export default function App() {
  const [url, setUrl] = useState('');
  const [cryptoScamEnabled, setCryptoScamEnabled] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [assessmentId, setAssessmentId] = useState<string | null>(null);
  const [assessment, setAssessment] = useState<AssessmentDetail | null>(null);

  // Proactively initialize visitor session on page load
  useEffect(() => {
    getOrInitVisitorSession().catch((err) => {
      console.warn('Initial visitor session handshake failed:', err);
    });
  }, []);

  // Poll assessment while queued or running
  useEffect(() => {
    if (!assessmentId) return;

    const interval = setInterval(async () => {
      try {
        const data = await getAssessment(assessmentId);
        setAssessment(data);
        if (data.status === 'completed' || data.status === 'partial' || data.status === 'failed' || data.status === 'cancelled') {
          clearInterval(interval);
          setLoading(false);
        }
      } catch (err: any) {
        setError(err.message || 'Failed to retrieve assessment details');
        clearInterval(interval);
        setLoading(false);
      }
    }, 1500);

    return () => clearInterval(interval);
  }, [assessmentId]);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url) return;

    setError(null);
    setLoading(true);
    setAssessment(null);

    try {
      const formattedUrl = url.startsWith('http') ? url : `https://${url}`;
      const res = await createAssessment({
        url: formattedUrl,
        authorization: { attested: true },
        safeScan: { enabled: false },
        options: {
          cryptoScamAnalysis: cryptoScamEnabled,
        },
      });
      setAssessmentId(res.assessmentId);
    } catch (err: any) {
      setError(err.message || 'Failed to initialize security assessment');
      setLoading(false);
    }
  };

  const getScoreColor = (score: number) => {
    if (score < 20) return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
    if (score < 50) return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
    if (score < 75) return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
    return 'text-rose-400 bg-rose-500/10 border-rose-500/30';
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'bg-rose-500/20 text-rose-400 border-rose-500/30';
      case 'high':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'medium':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
      case 'low':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const getAssessmentStatusBadge = (status: string) => {
    switch (status) {
      case 'completed':
        return 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400';
      case 'partial':
        return 'bg-amber-500/10 border-amber-500/30 text-amber-400';
      case 'running':
        return 'bg-sky-500/10 border-sky-500/30 text-sky-400 animate-pulse';
      case 'queued':
        return 'bg-blue-500/10 border-blue-500/30 text-blue-400';
      case 'failed':
        return 'bg-rose-500/10 border-rose-500/30 text-rose-400';
      default:
        return 'bg-slate-800 border-slate-700 text-slate-400';
    }
  };

  const getAgentStatus = (agentKey: string) => {
    if (!assessment) return { label: 'Queued', color: 'text-slate-500' };
    const run = assessment.agentRuns?.find(
      (r) => r.agentName.toLowerCase() === agentKey.toLowerCase()
    );
    if (!run) {
      if (assessment.status === 'queued') return { label: 'Queued', color: 'text-blue-400' };
      if (assessment.status === 'running') return { label: 'Running...', color: 'text-sky-400' };
      return { label: 'Not Executed', color: 'text-slate-500' };
    }
    switch (run.status) {
      case 'completed':
        return { label: 'Completed', color: 'text-emerald-400' };
      case 'running':
        return { label: 'Running...', color: 'text-sky-400' };
      case 'partial':
        return { label: 'Partial', color: 'text-amber-400' };
      case 'failed':
        return { label: 'Failed', color: 'text-rose-400' };
      case 'unavailable':
        return { label: 'Unavailable', color: 'text-slate-400' };
      case 'timeout':
        return { label: 'Timed Out', color: 'text-rose-400' };
      case 'queued':
      default:
        return { label: 'Queued', color: 'text-blue-400' };
    }
  };

  const getCheckBadge = (status?: CheckStatus) => {
    if (!status || status === 'not_requested') {
      return { label: 'Not Requested', class: 'bg-slate-800 text-slate-400 border-slate-700' };
    }
    if (status === 'passed' || status === 'good' || status === 'completed') {
      return { label: status === 'good' ? 'Good' : 'Passed', class: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' };
    }
    if (status === 'failed' || status === 'revoked') {
      return { label: status === 'revoked' ? 'Revoked' : 'Failed', class: 'bg-rose-500/10 text-rose-400 border-rose-500/30' };
    }
    if (status === 'unavailable') {
      return { label: 'Unavailable', class: 'bg-slate-800 text-slate-400 border-slate-700' };
    }
    // unknown - explicitly never passed
    return { label: 'Unknown', class: 'bg-amber-500/10 text-amber-400 border-amber-500/30' };
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      {/* Top Navbar */}
      <header className="border-b border-slate-800 bg-slate-900/50 backdrop-blur sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-emerald-500/10 border border-emerald-500/20 rounded-lg text-emerald-400">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <span className="text-xl font-bold tracking-tight text-white">Trust<span className="text-emerald-400">Lens</span></span>
              <span className="ml-2 text-xs uppercase px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">Digital Trust Engine</span>
            </div>
          </div>
          <div className="flex items-center space-x-4 text-sm text-slate-400">
            <span className="flex items-center gap-1"><CheckCircle className="w-4 h-4 text-emerald-400" /> 6 Deterministic Agents</span>
            <span className="hidden sm:inline border-l border-slate-800 pl-4">v0.1.0</span>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 py-8 flex flex-col items-center">
        {/* Hero & Scanner Input */}
        <div className="w-full max-w-3xl text-center mb-8">
          <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight mb-3">
            Automated Web Threat & Digital Trust Intelligence
          </h1>
          <p className="text-slate-400 text-sm sm:text-base mb-6">
            Assess target domains for phishing impersonation, TLS certificate weaknesses, redirect traps, and privacy exposures without intrusive exploitation.
          </p>

          <form onSubmit={handleScan} className="flex flex-col gap-3">
            <div className="flex flex-col sm:flex-row gap-2">
              <div className="relative flex-1">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                  <Globe className="w-5 h-5" />
                </div>
                <input
                  type="text"
                  placeholder="Enter URL to inspect (e.g. example.com or https://paypal-login-verify.com)"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  className="w-full pl-10 pr-4 py-3 bg-slate-900 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-transparent text-sm"
                />
              </div>
              <button
                type="submit"
                disabled={loading || !url}
                className="px-6 py-3 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-medium rounded-lg text-sm transition flex items-center justify-center gap-2"
              >
                {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                {loading ? 'Analyzing...' : 'Analyze Website'}
              </button>
            </div>

            <div className="flex items-center justify-start gap-2 px-1 text-xs text-slate-400">
              <input
                type="checkbox"
                id="cryptoScam"
                checked={cryptoScamEnabled}
                onChange={(e) => setCryptoScamEnabled(e.target.checked)}
                className="rounded border-slate-700 text-emerald-500 focus:ring-emerald-500 bg-slate-900"
              />
              <label htmlFor="cryptoScam" className="cursor-pointer select-none">
                Enable Cryptocurrency Scam Analysis (Disabled by default; runs only behind server flag)
              </label>
            </div>
          </form>

          {error && (
            <div className="mt-4 p-3 bg-rose-500/10 border border-rose-500/20 text-rose-400 rounded-lg text-sm flex items-center gap-2 text-left">
              <AlertTriangle className="w-4 h-4 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}
        </div>

        {/* Live Scan Results / Digital Trust Passport */}
        {assessment && (
          <div className="w-full max-w-4xl space-y-6 animate-fadeIn">
            {/* Top Passport Card */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 shadow-xl">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-xs uppercase px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-mono">Target Domain</span>
                    <span className={`text-xs uppercase px-2 py-0.5 rounded font-medium border ${getAssessmentStatusBadge(assessment.status)}`}>
                      {assessment.status}
                    </span>
                  </div>
                  <h2 className="text-xl font-bold text-white flex items-center gap-2">
                    {assessment.target}
                    <a href={assessment.target} target="_blank" rel="noreferrer" className="text-slate-500 hover:text-slate-300">
                      <ExternalLink className="w-4 h-4" />
                    </a>
                  </h2>
                </div>

                {/* Score Dial */}
                <div className={`flex items-center gap-3 px-4 py-2 rounded-xl border ${getScoreColor(assessment.risk?.score ?? 0)}`}>
                  <div className="text-right">
                    <div className="text-xs font-semibold uppercase tracking-wider">Risk Score</div>
                    <div className="text-xs capitalize opacity-80">{assessment.risk?.band ?? 'Low'} Risk</div>
                  </div>
                  <div className="text-3xl font-black">{assessment.risk?.score ?? 0}</div>
                </div>
              </div>

              {/* Six Agent Grid Status — Live & Truthful */}
              <div className="pt-6">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3">Deterministic Agent Statuses</h4>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                  {[
                    { key: 'url-redirect', name: 'URL & Redirect', icon: Globe },
                    { key: 'phishing-brand', name: 'Phishing & Brand', icon: AlertTriangle },
                    { key: 'certificate-intelligence', name: 'Certificate Intel', icon: Lock },
                    { key: 'safe-surface', name: 'Safe Surface', icon: Server },
                    { key: 'privacy-software', name: 'Privacy & Cookies', icon: FileText },
                    { key: 'threat-intelligence', name: 'Threat Intel Feed', icon: Shield },
                  ].map((ag, i) => {
                    const st = getAgentStatus(ag.key);
                    return (
                      <div key={i} className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg flex items-center gap-3">
                        <ag.icon className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                        <div className="overflow-hidden">
                          <div className="text-xs font-medium text-slate-300 truncate">{ag.name}</div>
                          <div className={`text-[10px] font-mono font-medium ${st.color}`}>{st.label}</div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Truthful Security & Trust Checks */}
              {assessment.checks && (
                <div className="pt-6 border-t border-slate-800/80 mt-6">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3">Security & Trust Checks</h4>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
                    {[
                      { key: 'ct', name: 'Cert Transparency', status: assessment.checks.ct },
                      { key: 'revocation', name: 'Revocation (OCSP/CRL)', status: assessment.checks.revocation },
                      { key: 'safeScan', name: 'Safe Surface Scan', status: assessment.checks.safeScan },
                      { key: 'caChain', name: 'Trusted CA Chain', status: assessment.checks.caChain },
                      { key: 'hostnameMatch', name: 'Hostname / SAN', status: assessment.checks.hostnameMatch },
                      { key: 'validityDates', name: 'Validity Period', status: assessment.checks.validityDates },
                      { key: 'tlsConfiguration', name: 'TLS Version & Cipher', status: assessment.checks.tlsConfiguration },
                      { key: 'cryptoStrength', name: 'Cryptographic Strength', status: assessment.checks.cryptoStrength },
                    ].map((chk, idx) => {
                      const badge = getCheckBadge(chk.status);
                      return (
                        <div key={idx} className="p-2.5 bg-slate-950/40 border border-slate-800/80 rounded-lg flex flex-col justify-between">
                          <span className="text-[11px] text-slate-400 font-medium truncate mb-1">{chk.name}</span>
                          <span className={`text-[10px] uppercase font-mono px-1.5 py-0.5 rounded border inline-block w-fit ${badge.class}`}>
                            {badge.label}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>

            {/* Findings Section */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 shadow-xl">
              <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                <Info className="w-5 h-5 text-emerald-400" />
                Security & Trust Findings ({assessment.findings?.length ?? 0})
              </h3>

              {!assessment.findings || assessment.findings.length === 0 ? (
                <div className="text-center py-8 text-slate-500 text-sm">
                  {assessment.status === 'running' || assessment.status === 'queued'
                    ? 'Assessment in progress — awaiting agent findings...'
                    : 'No high-risk indicators or malicious signals detected on this target.'}
                </div>
              ) : (
                <div className="space-y-3">
                  {assessment.findings.map((f: Finding) => (
                    <div key={f.findingId} className="p-4 bg-slate-950 border border-slate-800/80 rounded-lg hover:border-slate-700 transition">
                      <div className="flex items-center justify-between gap-2 mb-1.5">
                        <span className="text-sm font-semibold text-white">{f.title}</span>
                        <span className={`text-[11px] uppercase tracking-wider px-2 py-0.5 rounded font-mono border ${getSeverityBadge(f.severity)}`}>
                          {f.severity}
                        </span>
                      </div>
                      <div className="flex items-center gap-4 text-xs text-slate-500">
                        <span>Agent: <strong className="text-slate-400 font-normal">{f.agent}</strong></span>
                        <span>Type: <code className="text-slate-400 font-mono text-[11px]">{f.type}</code></span>
                        <span>Confidence: <strong className="text-slate-400 font-normal">{(f.confidence * 100).toFixed(0)}%</strong></span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 py-6 text-center text-xs text-slate-600">
        TrustLens Platform — Authorized web-security & digital trust assessment engine. Non-intrusive scanning only.
      </footer>
    </div>
  );
}
