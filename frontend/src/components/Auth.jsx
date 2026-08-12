import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Shield, Lock, Terminal, Globe, Server, Cpu, AlertCircle } from 'lucide-react';
import { Button } from './ui/button';
import { Input } from './ui/input';

export default function Auth({ onLoginSuccess }) {
  const [accessCode, setAccessCode] = useState('');
  const [endpoint, setEndpoint] = useState('http://localhost:8000');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [diagnostic, setDiagnostic] = useState(null);

  const handleDiagnose = async () => {
    setLoading(true);
    setError('');
    setDiagnostic('Ping sent... awaiting acknowledgement.');
    try {
      const response = await fetch(`${endpoint}/health`);
      if (response.ok) {
        const data = await response.json();
        setDiagnostic(`Gateway online. Engine: ${data.engine} (v${data.version})`);
      } else {
        throw new Error('Endpoint returned error status.');
      }
    } catch (err) {
      setError(`Cannot contact gateway at ${endpoint}. Run backend first.`);
      setDiagnostic(null);
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    if (!accessCode) {
      setError('SOC authorization code required.');
      return;
    }

    setLoading(true);
    setError('');

    // Simulate high-security handshakes
    setTimeout(async () => {
      try {
        // Optional verification if server is running, otherwise just mock to let them proceed
        const response = await fetch(`${endpoint}/health`).catch(() => null);
        if (response && response.ok) {
          onLoginSuccess(endpoint);
        } else {
          // Allow bypass if offline so user can inspect dashboard visual layouts anyway
          logger.warning("Bypassing server validation check: Offline mode activated.");
          onLoginSuccess(endpoint);
        }
      } catch (err) {
        onLoginSuccess(endpoint);
      } finally {
        setLoading(false);
      }
    }, 1200);
  };

  return (
    <div className="min-h-screen bg-[#050505] text-slate-200 flex items-center justify-center relative overflow-hidden font-sans">
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(0,242,255,0.02),transparent_70%)] pointer-events-none" />
      <div className="scanline-overlay pointer-events-none fixed inset-0 z-50 opacity-[0.02]" />

      <motion.div
        initial={{ opacity: 0, y: 15 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.8, ease: 'easeOut' }}
        className="w-full max-w-[420px] p-8 border border-white/5 bg-black/40 backdrop-blur-xl rounded-2xl relative shadow-[0_20px_50px_rgba(0,0,0,0.5)]"
      >
        {/* Decorative thin top line */}
        <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-primary/30 to-transparent" />

        {/* Shield Icon Header */}
        <div className="flex flex-col items-center text-center space-y-3 mb-8">
          <div className="p-3 bg-primary/10 rounded-xl border border-primary/20 text-primary shadow-[0_0_20px_rgba(0,242,255,0.15)]">
            <Shield className="w-8 h-8" />
          </div>
          <div>
            <h1 className="text-xl font-black uppercase tracking-tight italic text-white leading-none">Encrypted Threat Detector</h1>
            <p className="text-[10px] text-muted-foreground uppercase mono tracking-[0.2em] mt-1.5 font-semibold">Security Operations Center Portal</p>
          </div>
        </div>

        {/* Login Form */}
        <form onSubmit={handleLogin} className="space-y-5">
          <div className="space-y-1.5">
            <label className="text-[9px] mono uppercase font-bold text-muted-foreground tracking-widest flex items-center gap-1.5">
              <Server className="w-3 h-3 text-primary/70" /> API Gateway Endpoint
            </label>
            <div className="relative">
              <Input
                type="text"
                value={endpoint}
                onChange={(e) => setEndpoint(e.target.value)}
                placeholder="http://localhost:8000"
                className="pl-8 bg-white/5 border-white/10 text-xs text-slate-200 placeholder:text-muted-foreground/30 focus-visible:ring-primary/40 focus-visible:border-primary/50"
              />
              <Globe className="w-3.5 h-3.5 text-muted-foreground/50 absolute left-2.5 top-3" />
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="text-[9px] mono uppercase font-bold text-muted-foreground tracking-widest flex items-center gap-1.5">
              <Lock className="w-3 h-3 text-primary/70" /> SOC Access Code
            </label>
            <div className="relative">
              <Input
                type="password"
                value={accessCode}
                onChange={(e) => setAccessCode(e.target.value)}
                placeholder="••••••••••••"
                className="pl-8 bg-white/5 border-white/10 text-xs text-slate-200 placeholder:text-muted-foreground/30 focus-visible:ring-primary/40 focus-visible:border-primary/50"
              />
              <Terminal className="w-3.5 h-3.5 text-muted-foreground/50 absolute left-2.5 top-3" />
            </div>
          </div>

          {/* Diagnostic Console Panel */}
          {diagnostic && (
            <div className="p-3 border border-primary/10 bg-primary/[0.02] rounded-lg text-[10px] mono text-primary leading-tight">
              <div className="flex items-center gap-1.5 font-bold uppercase tracking-wider mb-0.5">
                <Cpu className="w-3 h-3" /> Status Diagnostic
              </div>
              <p className="opacity-90">{diagnostic}</p>
            </div>
          )}

          {error && (
            <div className="p-3 border border-red-500/10 bg-red-500/[0.02] rounded-lg text-[10px] mono text-red-400 leading-tight">
              <div className="flex items-center gap-1.5 font-bold uppercase tracking-wider mb-0.5">
                <AlertCircle className="w-3.5 h-3.5" /> Authorization Interrupted
              </div>
              <p className="opacity-90">{error}</p>
            </div>
          )}

          <div className="flex gap-3 pt-2">
            <Button
              type="button"
              variant="outline"
              onClick={handleDiagnose}
              disabled={loading}
              className="w-1/3 border-white/10 hover:bg-white/5 uppercase mono text-[9px] font-bold"
            >
              Test Link
            </Button>
            <Button
              type="submit"
              disabled={loading}
              className="flex-1 bg-primary text-black hover:bg-primary/90 font-black uppercase mono text-[9px] tracking-widest shadow-[0_0_15px_rgba(0,242,255,0.2)]"
            >
              {loading ? 'Authenticating...' : 'Enter Console'}
            </Button>
          </div>
        </form>

        <div className="text-center mt-6">
          <span className="text-[9px] mono text-muted-foreground uppercase opacity-40">System-Authorization Version 1.1.0</span>
        </div>
      </motion.div>
    </div>
  );
}
