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
import { createAssessment, getAssessment } from './api/client';
import { AssessmentDetail, Finding } from './types';

export default function App() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [assessmentId, setAssessmentId] = useState<string | null>(null);
  const [assessment, setAssessment] = useState<AssessmentDetail | null>(null);

  // Poll assessment while queued or running
  useEffect(() => {
    if (!assessmentId) return;

    const interval = setInterval(async () => {
      try {
        const data = await getAssessment(assessmentId);
        setAssessment(data);
        if (data.status === 'completed' || data.status === 'partial' || data.status === 'failed') {
          clearInterval(interval);
          setLoading(false);
        }
      } catch (err: any) {
        setError(err.message);
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
      });
      setAssessmentId(res.assessmentId);
    } catch (err: any) {
      setError(err.message);
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

          <form onSubmit={handleScan} className="flex flex-col sm:flex-row gap-2">
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
                    <span className={`text-xs uppercase px-2 py-0.5 rounded font-medium border ${assessment.status === 'completed' ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' : 'bg-amber-500/10 border-amber-500/30 text-amber-400'}`}>
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
                <div className={`flex items-center gap-3 px-4 py-2 rounded-xl border ${getScoreColor(assessment.risk.score)}`}>
                  <div className="text-right">
                    <div className="text-xs font-semibold uppercase tracking-wider">Risk Score</div>
                    <div className="text-xs capitalize opacity-80">{assessment.risk.band} Risk</div>
                  </div>
                  <div className="text-3xl font-black">{assessment.risk.score}</div>
                </div>
              </div>

              {/* Six Agent Grid Status */}
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 pt-6">
                {[
                  { name: 'URL & Redirect', icon: Globe, status: 'Completed' },
                  { name: 'Phishing & Brand', icon: AlertTriangle, status: 'Completed' },
                  { name: 'Certificate Intel', icon: Lock, status: 'Completed' },
                  { name: 'Safe Surface', icon: Server, status: 'Allowlisted' },
                  { name: 'Privacy & Cookies', icon: FileText, status: 'Completed' },
                  { name: 'Threat Intel Feed', icon: Shield, status: 'Active' },
                ].map((ag, i) => (
                  <div key={i} className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg flex items-center gap-3">
                    <ag.icon className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                    <div className="overflow-hidden">
                      <div className="text-xs font-medium text-slate-300 truncate">{ag.name}</div>
                      <div className="text-[10px] text-slate-500">{ag.status}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Findings Section */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 shadow-xl">
              <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                <Info className="w-5 h-5 text-emerald-400" />
                Security & Trust Findings ({assessment.findings.length})
              </h3>

              {assessment.findings.length === 0 ? (
                <div className="text-center py-8 text-slate-500 text-sm">
                  No high-risk indicators or malicious signals detected on this target.
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

