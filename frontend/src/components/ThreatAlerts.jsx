import React, { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  ShieldAlert, Shield, Search, X, ChevronRight, AlertTriangle, Eye, 
  MapPin, Globe, Terminal, Calendar, Activity, Info
} from 'lucide-react';
import { Card } from './ui/card';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import { Input } from './ui/input';
import { Separator } from './ui/separator';

export default function ThreatAlerts({ apiEndpoint, alerts, onRefresh }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [selectedAlertId, setSelectedAlertId] = useState(null);
  const [alertDetails, setAlertDetails] = useState(null);
  const [loadingDetails, setLoadingDetails] = useState(false);

  // Compute severity counts
  const counts = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0
  };

  alerts.forEach(a => {
    if (counts[a.severity] !== undefined) {
      counts[a.severity]++;
    }
  });

  // Fetch alert detail (full JSON raw data with SHAP values)
  const handleSelectAlert = async (flowId) => {
    setSelectedAlertId(flowId);
    setLoadingDetails(true);
    setAlertDetails(null);
    try {
      const response = await fetch(`${apiEndpoint}/api/flows/${flowId}`);
      if (response.ok) {
        const data = await response.json();
        setAlertDetails(data);
      }
    } catch (err) {
      console.error("Failed to load flow detail:", err);
    } finally {
      setLoadingDetails(false);
    }
  };

  // Filter alerts
  const filteredAlerts = alerts.filter(a => {
    const matchesSearch = 
      a.src_ip.includes(searchTerm) || 
      a.dst_ip.includes(searchTerm) || 
      (a.sni && a.sni.toLowerCase().includes(searchTerm.toLowerCase()));
      
    const matchesSeverity = severityFilter === 'ALL' || a.severity === severityFilter;
    
    return matchesSearch && matchesSeverity;
  });

  return (
    <div className="space-y-6 relative">
      {/* Header controls panel */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-4 border-b border-white/5 pb-6">
        <div>
          <h2 className="text-2xl font-black tracking-tight text-white uppercase italic">Active Threat Registry</h2>
          <p className="text-[10px] text-muted-foreground uppercase mono tracking-[0.15em] mt-1">
            Historical logs of ML-classified threat events and signatures
          </p>
        </div>
        {onRefresh && (
          <Button onClick={onRefresh} variant="outline" className="border-white/10 hover:bg-white/5 uppercase mono text-[9px] font-bold">
            Synchronize Logs
          </Button>
        )}
      </div>

      {/* Severity Counters cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {Object.entries(counts).map(([sev, count]) => {
          const colorClass = 
            sev === 'Critical' ? 'text-[#FF3B30] border-[#FF3B30]/10 bg-[#FF3B30]/[0.02]' :
            sev === 'High' ? 'text-[#FF9500] border-[#FF9500]/10 bg-[#FF9500]/[0.02]' :
            sev === 'Medium' ? 'text-[#FFCC00] border-[#FFCC00]/10 bg-[#FFCC00]/[0.02]' :
            'text-[#3498DB] border-[#3498DB]/10 bg-[#3498DB]/[0.02]';
          return (
            <Card 
              key={sev}
              onClick={() => setSeverityFilter(severityFilter === sev ? 'ALL' : sev)}
              className={`p-4 border cursor-pointer hover:border-white/20 transition-all text-center space-y-1 ${colorClass} ${severityFilter === sev ? 'ring-1 ring-white/20' : ''}`}
            >
              <div className="text-[10px] uppercase font-bold mono tracking-widest">{sev}</div>
              <div className="text-3xl font-black">{count}</div>
            </Card>
          );
        })}
      </div>

      {/* Filter and search controls */}
      <div className="flex flex-col md:flex-row gap-4 items-center justify-between">
        <div className="relative w-full md:w-80">
          <Search className="absolute left-2.5 top-3.5 h-3.5 w-3.5 text-muted-foreground" />
          <Input 
            placeholder="Search IPs or SNI..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-8 bg-white/5 border-white/10 text-xs focus-visible:ring-primary/30"
          />
        </div>
        <div className="flex gap-2 w-full md:w-auto">
          {['ALL', 'Critical', 'High', 'Medium', 'Low'].map(sev => (
            <Button
              key={sev}
              size="sm"
              variant={severityFilter === sev ? 'default' : 'outline'}
              onClick={() => setSeverityFilter(sev)}
              className="uppercase mono text-[9px] font-bold"
            >
              {sev}
            </Button>
          ))}
        </div>
      </div>

      {/* Alerts list */}
      <div className="space-y-3">
        {filteredAlerts.length > 0 ? (
          filteredAlerts.map(alert => {
            const isCritical = alert.severity === 'Critical';
            const dateStr = alert.timestamp ? new Date(alert.timestamp * 1000).toLocaleString() : 'N/A';
            return (
              <Card 
                key={alert.flow_id}
                onClick={() => handleSelectAlert(alert.flow_id)}
                className={`p-4 border ${selectedAlertId === alert.flow_id ? 'border-primary/50' : 'border-white/5'} bg-black/40 hover:bg-black/60 transition-colors flex items-center justify-between cursor-pointer`}
              >
                <div className="flex items-center gap-4">
                  <div className={`p-2 rounded-lg border ${isCritical ? 'border-threat/20 text-threat bg-threat/10' : 'border-amber-500/20 text-amber-500 bg-amber-500/10'}`}>
                    <ShieldAlert className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-bold text-white mono">{alert.src_ip} → {alert.dst_ip}</span>
                      <Badge variant={alert.severity.toLowerCase()}>{alert.severity}</Badge>
                    </div>
                    <div className="text-[10px] text-muted-foreground mono mt-1">
                      SNI: <span className="text-primary">{alert.sni || 'N/A'}</span> • Risk Index: <span className="text-threat font-bold">{alert.risk_score}</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-4 text-right">
                  <div className="hidden md:block text-[10px] text-muted-foreground mono">
                    {dateStr}
                  </div>
                  <ChevronRight className="w-4 h-4 text-muted-foreground/60" />
                </div>
              </Card>
            );
          })
        ) : (
          <div className="text-center py-24 text-[10px] mono text-muted-foreground uppercase tracking-widest border border-dashed border-white/5 rounded-xl bg-black/20">
            No threat logs matching current filters.
          </div>
        )}
      </div>

      {/* Slide-over details drawer (Framer Motion) */}
      <AnimatePresence>
        {selectedAlertId && (
          <>
            {/* Backdrop click barrier */}
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 0.5 }}
              exit={{ opacity: 0 }}
              onClick={() => setSelectedAlertId(null)}
              className="fixed inset-0 bg-black z-50 pointer-events-auto"
            />
            
            {/* Drawer */}
            <motion.div
              initial={{ x: '100%' }}
              animate={{ x: 0 }}
              exit={{ x: '100%' }}
              transition={{ type: 'spring', damping: 25, stiffness: 200 }}
              className="fixed right-0 top-0 h-full w-full max-w-[500px] bg-[#0A0A0C] border-l border-white/10 z-[100] p-6 shadow-[-10px_0_40px_rgba(0,0,0,0.8)] overflow-y-auto flex flex-col justify-between"
            >
              <div className="space-y-6">
                {/* Header */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Shield className="w-4 h-4 text-primary" />
                    <span className="text-[9px] mono uppercase font-bold text-muted-foreground tracking-widest">Alert Profile</span>
                  </div>
                  <Button size="icon" variant="ghost" onClick={() => setSelectedAlertId(null)} className="h-8 w-8 text-muted-foreground hover:text-white">
                    <X className="w-4 h-4" />
                  </Button>
                </div>

                {loadingDetails ? (
                  <div className="flex flex-col items-center justify-center py-40 space-y-3">
                    <Loader2 className="w-8 h-8 text-primary animate-spin" />
                    <span className="text-[10px] mono uppercase tracking-wider text-muted-foreground">Gathering forensic logs...</span>
                  </div>
                ) : alertDetails ? (
                  <div className="space-y-6">
                    {/* Summary profile */}
                    <div className="space-y-2">
                      <div className="flex items-center gap-2">
                        <Badge variant={alertDetails.severity?.toLowerCase() || 'threat'}>
                          {alertDetails.severity} SEVERITY
                        </Badge>
                        <span className="text-[9px] mono text-muted-foreground uppercase">Flow ID: {alertDetails.flow_id?.substring(0, 8)}</span>
                      </div>
                      <h3 className="text-base font-black text-white mono">{alertDetails.src_ip} → {alertDetails.dst_ip}</h3>
                    </div>

                    <Separator className="bg-white/5" />

                    {/* Sockets Details */}
                    <div className="space-y-2">
                      <h4 className="text-[9px] uppercase font-bold text-muted-foreground tracking-widest">Network Context</h4>
                      <div className="grid grid-cols-2 gap-4 text-[10px] mono bg-white/[0.01] border border-white/5 p-3 rounded-lg">
                        <div className="space-y-0.5">
                          <span className="text-muted-foreground text-[8px] uppercase">Src Socket</span>
                          <div className="text-white font-bold">{alertDetails.src_ip}:{alertDetails.src_port}</div>
                        </div>
                        <div className="space-y-0.5">
                          <span className="text-muted-foreground text-[8px] uppercase">Dst Socket</span>
                          <div className="text-white font-bold">{alertDetails.dst_ip}:{alertDetails.dst_port}</div>
                        </div>
                        <div className="col-span-2 space-y-0.5">
                          <span className="text-muted-foreground text-[8px] uppercase">TLS Target Server (SNI)</span>
                          <div className="text-primary font-bold">{alertDetails.sni || 'N/A'}</div>
                        </div>
                      </div>
                    </div>

                    {/* Reputation threat intelligence */}
                    <div className="space-y-2">
                      <h4 className="text-[9px] uppercase font-bold text-muted-foreground tracking-widest">Threat Intelligence Analysis</h4>
                      <div className="grid grid-cols-3 gap-2 text-center text-[10px] mono">
                        <div className="p-3 border border-white/5 bg-white/[0.01] rounded-lg">
                          <div className="text-[8px] text-muted-foreground uppercase">IP score</div>
                          <div className="text-sm font-black text-threat mt-1">{alertDetails.ip_reputation_score || 0}%</div>
                        </div>
                        <div className="p-3 border border-white/5 bg-white/[0.01] rounded-lg">
                          <div className="text-[8px] text-muted-foreground uppercase">Domain reputation</div>
                          <div className="text-sm font-black text-threat mt-1">{alertDetails.domain_reputation_score || 0}%</div>
                        </div>
                        <div className="p-3 border border-white/5 bg-white/[0.01] rounded-lg">
                          <div className="text-[8px] text-muted-foreground uppercase">Cert risk</div>
                          <div className="text-sm font-black text-amber-500 mt-1">{alertDetails.cert_risk_score || 0}/100</div>
                        </div>
                      </div>
                      
                      {alertDetails.ja3_match && (
                        <div className="p-3 border border-red-500/20 bg-red-500/[0.02] rounded-lg text-[10px] mono text-threat leading-tight flex items-start gap-2">
                          <Info className="w-4 h-4 shrink-0 mt-0.5" />
                          <div>
                            <span className="font-bold uppercase tracking-wider block">Local JA3 signature match</span>
                            <p className="opacity-95 mt-0.5">Hash matches payload signature linked to: <b>{alertDetails.ja3_threat_label}</b></p>
                          </div>
                        </div>
                      )}
                    </div>

                    {/* SHAP machine learning feature contributions */}
                    {alertDetails.top_features && alertDetails.top_features.length > 0 && (
                      <div className="space-y-2.5">
                        <h4 className="text-[9px] uppercase font-bold text-muted-foreground tracking-widest">Forensic Explainer (SHAP)</h4>
                        <div className="space-y-2.5">
                          {alertDetails.top_features.map((feat, idx) => (
                            <div key={idx} className="space-y-1">
                              <div className="flex justify-between text-[9px] mono uppercase font-bold text-muted-foreground">
                                <span className="truncate max-w-[240px]">{feat.feature}</span>
                                <span>{(feat.importance).toFixed(4)}</span>
                              </div>
                              <div className="h-1.5 w-full bg-white/5 rounded-full overflow-hidden">
                                <div 
                                  className="h-full rounded-full bg-threat" 
                                  style={{ width: `${Math.min(100, feat.importance * 200)}%` }} 
                                />
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="text-center py-20 text-[10px] text-muted-foreground mono uppercase">
                     forensic logs unavailable.
                  </div>
                )}
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </div>
  );
}
