import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { 
  Search, ShieldAlert, ShieldCheck, Globe, Database, Terminal, 
  MapPin, AlertTriangle, Key, Info, HelpCircle
} from 'lucide-react';
import { Card } from './ui/card';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Separator } from './ui/separator';

export default function ThreatIntel({ apiEndpoint }) {
  const [queryType, setQueryType] = useState('IP'); // IP, DOMAIN, JA3
  const [queryVal, setQueryVal] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState('');

  const handleLookup = async (e) => {
    e.preventDefault();
    if (!queryVal) return;

    setLoading(true);
    setError('');
    setResults(null);

    // Simulate contacting API
    setTimeout(async () => {
      try {
        if (queryType === 'IP') {
          // If private IP
          if (queryVal.startsWith('192.168.') || queryVal.startsWith('10.') || queryVal === '127.0.0.1') {
            setResults({
              query: queryVal,
              type: 'IP',
              status: 'CLEAN',
              label: 'Local Private Subnet',
              abuse_score: 0,
              vt_percentage: 0,
              details: 'IP is inside the local RFC1918 private networking range. Excluded from threat intel lookups.'
            });
            setLoading(false);
            return;
          }

          // Mock or call backend if running
          setResults({
            query: queryVal,
            type: 'IP',
            status: Math.random() > 0.4 ? 'CLEAN' : 'MALICIOUS',
            label: Math.random() > 0.4 ? 'Generic Cloud Provider' : 'Active Tor Exit Node / Botnet C2',
            abuse_score: Math.floor(Math.random() * 95),
            vt_percentage: Math.floor(Math.random() * 88),
            details: 'Multiple threat alerts registered in last 90 days. Recommended for firewall block.'
          });
        } 
        
        else if (queryType === 'DOMAIN') {
          setResults({
            query: queryVal,
            type: 'DOMAIN',
            status: Math.random() > 0.3 ? 'CLEAN' : 'MALICIOUS',
            label: Math.random() > 0.3 ? 'CDN Cache Server' : 'Fast-Flux DGA Phishing Server',
            vt_percentage: Math.floor(Math.random() * 94),
            details: 'Domain flagged for dynamic DNS switching behavior. Associated with malware download campaigns.'
          });
        } 
        
        else if (queryType === 'JA3') {
          const defaultJA3 = {
            "7c95e1e44383188fa6af70188ef3914a": "Cobalt Strike Beacon",
            "8947940c1ae8f31e67e9193153b9f915": "Emotet Downloader",
            "e2f6940c497475f49ce17c88ef39f915": "Sliver C2 Agent",
            "62ebf686c0c2d3cf3832d2f7f18ef391": "Trickbot Trojan Client"
          };
          const hash = queryVal.trim().lower();
          if (hash in defaultJA3) {
            setResults({
              query: queryVal,
              type: 'JA3',
              status: 'MALICIOUS',
              label: defaultJA3[hash],
              details: 'Critical Signature Match: ClientHello fingerprinted as an active command-and-control connection tool.'
            });
          } else {
            setResults({
              query: queryVal,
              type: 'JA3',
              status: 'CLEAN',
              label: 'Standard Web Client',
              details: 'Unknown signature. Corresponds to common browser ClientHello footprints.'
            });
          }
        }
      } catch (err) {
        setError('Threat Intel gateway lookup failed.');
      } finally {
        setLoading(false);
      }
    }, 1000);
  };

  return (
    <div className="space-y-6">
      {/* Header controls panel */}
      <div className="flex justify-between items-end border-b border-white/5 pb-6">
        <div>
          <h2 className="text-2xl font-black tracking-tight text-white uppercase italic">Threat Intelligence Lookup</h2>
          <p className="text-[10px] text-muted-foreground uppercase mono tracking-[0.15em] mt-1">
            Manual querying interface for reputation and local signature checks
          </p>
        </div>
      </div>

      <div className="max-w-3xl mx-auto space-y-6">
        {/* Search card */}
        <Card className="p-6 border border-white/5 bg-black/40 space-y-6 relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-primary/20 to-transparent" />
          
          {/* Tabs for query type */}
          <div className="flex gap-2">
            {['IP', 'DOMAIN', 'JA3'].map(type => (
              <Button
                key={type}
                type="button"
                variant={queryType === type ? 'default' : 'outline'}
                onClick={() => {
                  setQueryType(type);
                  setQueryVal('');
                  setResults(null);
                }}
                className="uppercase mono text-[9px] font-bold px-4"
              >
                {type === 'IP' ? <MapPin className="w-3.5 h-3.5 mr-1.5" /> : 
                 type === 'DOMAIN' ? <Globe className="w-3.5 h-3.5 mr-1.5" /> : 
                 <Key className="w-3.5 h-3.5 mr-1.5" />}
                {type}
              </Button>
            ))}
          </div>

          {/* Form */}
          <form onSubmit={handleLookup} className="flex gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-2.5 top-3.5 h-4 w-4 text-muted-foreground" />
              <Input
                type="text"
                value={queryVal}
                onChange={(e) => setQueryVal(e.target.value)}
                placeholder={
                  queryType === 'IP' ? 'Enter target IP (e.g. 185.220.101.4)' : 
                  queryType === 'DOMAIN' ? 'Enter host SNI (e.g. malicious-server.ru)' : 
                  'Enter MD5 JA3 hash (e.g. 7c95e1e44383188fa6af70188ef3914a)'
                }
                className="pl-9 bg-white/5 border-white/10 text-xs focus-visible:ring-primary/30"
              />
            </div>
            <Button type="submit" disabled={loading || !queryVal} className="bg-primary text-black hover:bg-primary/95 font-bold uppercase mono text-[9px] tracking-widest px-6 shadow-[0_0_15px_rgba(0,242,255,0.2)]">
              {loading ? 'Searching...' : 'Lookup'}
            </Button>
          </form>
        </Card>

        {/* Results view */}
        <AnimatePresence>
          {results && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="space-y-6"
            >
              {/* Profile Card */}
              <Card className="p-6 border border-white/5 bg-black/40 relative overflow-hidden">
                {results.status === 'MALICIOUS' ? (
                  <div className="absolute top-0 left-0 w-full h-[3px] bg-threat" />
                ) : (
                  <div className="absolute top-0 left-0 w-full h-[3px] bg-benign" />
                )}

                <div className="flex justify-between items-start">
                  <div className="space-y-1">
                    <div className="flex items-center gap-1.5 text-[9px] mono uppercase font-bold text-muted-foreground">
                      {results.status === 'MALICIOUS' ? (
                        <span className="text-threat flex items-center gap-1.5"><ShieldAlert className="w-4 h-4" /> Flagged Malicious</span>
                      ) : (
                        <span className="text-benign flex items-center gap-1.5"><ShieldCheck className="w-4 h-4" /> Rating Clean</span>
                      )}
                    </div>
                    <h3 className="text-lg font-black text-white mono">{results.query}</h3>
                    <p className="text-[10px] text-muted-foreground uppercase font-semibold">{results.label}</p>
                  </div>
                </div>

                <Separator className="bg-white/5 my-5" />

                <div className="space-y-4">
                  {/* Indicators grid */}
                  {results.type === 'IP' && (
                    <div className="grid grid-cols-2 gap-4">
                      <div className="p-3 border border-white/5 bg-white/[0.01] rounded-xl text-center">
                        <div className="text-[8px] text-muted-foreground uppercase font-bold mono">AbuseIPDB Confidence</div>
                        <div className="text-2xl font-black text-white mt-1">{results.abuse_score}%</div>
                      </div>
                      <div className="p-3 border border-white/5 bg-white/[0.01] rounded-xl text-center">
                        <div className="text-[8px] text-muted-foreground uppercase font-bold mono">VirusTotal Detection Rate</div>
                        <div className="text-2xl font-black text-white mt-1">{results.vt_percentage}%</div>
                      </div>
                    </div>
                  )}

                  {results.type === 'DOMAIN' && (
                    <div className="grid grid-cols-1 gap-4">
                      <div className="p-3 border border-white/5 bg-white/[0.01] rounded-xl text-center">
                        <div className="text-[8px] text-muted-foreground uppercase font-bold mono">VirusTotal Domain Malicious Votes</div>
                        <div className="text-2xl font-black text-white mt-1">{results.vt_percentage}%</div>
                      </div>
                    </div>
                  )}

                  {/* Forensic commentary */}
                  <div className="p-3 border border-white/5 bg-white/[0.01] rounded-lg text-[10px] mono leading-relaxed flex items-start gap-2">
                    <Info className="w-4 h-4 text-primary shrink-0 mt-0.5" />
                    <div>
                      <span className="font-bold text-slate-200 uppercase tracking-wide">Threat Report Summary</span>
                      <p className="opacity-90 mt-0.5">{results.details}</p>
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
