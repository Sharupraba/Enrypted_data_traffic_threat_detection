import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Search, Info, ShieldAlert, ShieldCheck, HelpCircle, Loader2 } from 'lucide-react';
import { Card } from './ui/card';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import { Input } from './ui/input';
import { Separator } from './ui/separator';

export default function ThreatIntel({ apiEndpoint }) {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const detectQueryType = (q) => {
    const clean = q.trim();
    if (!clean) return 'UNKNOWN';
    if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(clean)) return 'IP';
    if (/^[a-fA-F0-9]{32}$/.test(clean)) return 'JA3';
    return 'DOMAIN';
  };

  const queryType = detectQueryType(query);

  const handleSearch = async (e) => {
    e.preventDefault();
    const cleanQuery = query.trim();
    if (!cleanQuery) return;

    setLoading(true);
    setError('');
    setResult(null);

    const type = detectQueryType(cleanQuery);

    try {
      const response = await fetch(
        `${apiEndpoint}/api/intel/lookup?query=${encodeURIComponent(cleanQuery)}&query_type=${type}`
      );
      if (response.ok) {
        const data = await response.json();
        setResult(data);
      } else {
        throw new Error('Threat Intelligence registry lookup failed.');
      }
    } catch (err) {
      console.error(err);
      setError('Lookup failed. Please verify system gateway connection is online.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex justify-between items-end border-b border-slate-200 pb-6">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-slate-900">Universal Threat Intel Engine</h2>
          <p className="text-xs text-slate-500 mt-1">
            One-click search bar for IPs, domains, and JA3 malware signatures
          </p>
        </div>
      </div>

      <div className="max-w-3xl mx-auto space-y-6">
        {/* Search Input Card */}
        <Card className="p-6 border border-slate-200 bg-white space-y-4 relative overflow-hidden shadow-sm">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Search className="w-4 h-4 text-slate-500" />
              <span className="text-[10px] mono uppercase font-bold text-slate-700 tracking-wider">Universal Threat Search</span>
            </div>
            {query.trim() && (
              <Badge variant="outline" className="border-indigo-200 text-indigo-700 bg-indigo-50/50 mono text-[8px] uppercase font-bold">
                Auto-Detected: {queryType === 'IP' ? 'IP Address' : queryType === 'JA3' ? 'JA3 Fingerprint' : 'Domain Host'}
              </Badge>
            )}
          </div>

          <form onSubmit={handleSearch} className="flex gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-3 h-4 w-4 text-slate-400" />
              <Input 
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Enter IP (e.g. 185.220.101.4), Domain (e.g. malicious-server.com), or JA3 Hash..."
                className="pl-9 bg-white border-slate-200 text-xs text-slate-800 focus-visible:ring-slate-300 py-5"
              />
            </div>
            <Button 
              type="submit" 
              disabled={loading || !query.trim()}
              className="bg-slate-900 hover:bg-slate-800 text-white font-medium text-xs px-6"
            >
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : "Query Intel"}
            </Button>
          </form>

          {error && (
            <p className="text-[10px] text-red-600 font-bold uppercase mt-2">{error}</p>
          )}
        </Card>

        {/* Results Panel */}
        <AnimatePresence>
          {result && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="space-y-6"
            >
              <Card className="p-6 border border-slate-200 bg-white relative overflow-hidden shadow-sm">
                <div className={`absolute top-0 left-0 w-full h-[3px] ${result.status === 'MALICIOUS' ? 'bg-red-500' : 'bg-emerald-500'}`} />
                
                <div className="flex justify-between items-start">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2 text-[9px] mono uppercase font-bold text-slate-400">
                      {result.status === 'MALICIOUS' ? (
                        <span className="text-red-600 flex items-center gap-1.5 font-semibold">
                          <ShieldAlert className="w-4 h-4" /> Flagged Malicious
                        </span>
                      ) : (
                        <span className="text-emerald-600 flex items-center gap-1.5 font-semibold">
                          <ShieldCheck className="w-4 h-4" /> Rating Clean / Safe
                        </span>
                      )}
                      <Badge variant="outline" className="border-slate-200 text-slate-600 text-[8px]">
                        TYPE: {result.type}
                      </Badge>
                    </div>
                    <h3 className="text-lg font-bold text-slate-800 mono mt-1">{result.query}</h3>
                    <p className="text-xs text-indigo-600 font-semibold tracking-wide">{result.label}</p>
                  </div>
                </div>

                <Separator className="bg-slate-200 my-5" />

                <div className="space-y-4">
                  {result.type === 'IP' && (
                    <div className="grid grid-cols-2 gap-4">
                      <div className="p-4 border border-slate-200 bg-slate-50 rounded-xl text-center">
                        <div className="text-[8px] text-slate-500 uppercase font-bold mono">AbuseIPDB Confidence</div>
                        <div className="text-2xl font-bold text-red-600 mt-1 mono">{result.abuse_score || 0}%</div>
                      </div>
                      <div className="p-4 border border-slate-200 bg-slate-50 rounded-xl text-center">
                        <div className="text-[8px] text-slate-500 uppercase font-bold mono">VirusTotal Detection Rate</div>
                        <div className="text-2xl font-bold text-red-600 mt-1 mono">{result.vt_percentage || 0}%</div>
                      </div>
                    </div>
                  )}

                  {result.type === 'DOMAIN' && (
                    <div className="grid grid-cols-1 gap-4">
                      <div className="p-4 border border-slate-200 bg-slate-50 rounded-xl text-center">
                        <div className="text-[8px] text-slate-500 uppercase font-bold mono">VirusTotal Domain Reputation</div>
                        <div className="text-2xl font-bold text-red-600 mt-1 mono">{result.vt_percentage || 0}%</div>
                      </div>
                    </div>
                  )}

                  {result.type === 'JA3' && (
                    <div className="grid grid-cols-1 gap-4">
                      <div className="p-4 border border-slate-200 bg-slate-50 rounded-xl text-center">
                        <div className="text-[8px] text-slate-500 uppercase font-bold mono">JA3 Malware Signature Match</div>
                        <div className={`text-lg font-bold mt-1 mono ${result.status === 'MALICIOUS' ? 'text-red-600' : 'text-emerald-600'}`}>
                          {result.status === 'MALICIOUS' ? "CRITICAL MATCH DETECTED" : "UNRECOGNIZED SIGNATURE (SAFE)"}
                        </div>
                      </div>
                    </div>
                  )}

                  <div className="p-4 border border-slate-200 bg-slate-50 rounded-xl text-xs mono leading-relaxed flex items-start gap-3">
                    <Info className="w-4 h-4 text-slate-500 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-bold text-slate-700 uppercase tracking-wide">Threat Report Summary</span>
                      <p className="opacity-90 mt-1 text-slate-600">{result.details}</p>
                    </div>
                  </div>
                </div>
              </Card>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
