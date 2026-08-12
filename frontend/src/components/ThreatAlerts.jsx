import React, { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  ShieldAlert, Shield, Search, X, ChevronRight, AlertTriangle, Eye, 
  MapPin, Globe, Terminal, Calendar, Activity, Info, Loader2, CheckCircle2, ShieldCheck
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
  const [allowLoading, setAllowLoading] = useState(false);

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

  // Whitelist / Allow alert connection
  const handleAllowAlert = async (e, flowId) => {
    if (e) e.stopPropagation();
    setAllowLoading(true);
    try {
      const response = await fetch(`${apiEndpoint}/api/flows/${flowId}/allow`, {
        method: 'POST'
      });
      if (response.ok) {
        setSelectedAlertId(null);
        if (onRefresh) await onRefresh();
      }
    } catch (err) {
      console.error("Failed to whitelist threat:", err);
    } finally {
      setAllowLoading(false);
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
      <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-4 border-b border-slate-200 pb-6">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-slate-900">Active Threat Registry</h2>
          <p className="text-xs text-slate-500 mt-1">
            Historical logs of ML-classified threat events and signatures
          </p>
        </div>
        {onRefresh && (
          <Button onClick={onRefresh} variant="outline" className="border-slate-200 bg-white hover:bg-slate-50 text-xs font-medium">
            Synchronize Logs
          </Button>
        )}
      </div>

      {/* Severity Counters cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {Object.entries(counts).map(([sev, count]) => {
          const colorClass = 
            sev === 'Critical' ? 'text-red-600 border-red-200 bg-red-50/50' :
            sev === 'High' ? 'text-orange-600 border-orange-200 bg-orange-50/50' :
            sev === 'Medium' ? 'text-yellow-700 border-yellow-200 bg-yellow-50/50' :
            'text-blue-600 border-blue-200 bg-blue-50/50';
          return (
            <Card 
              key={sev}
              onClick={() => setSeverityFilter(severityFilter === sev ? 'ALL' : sev)}
              className={`p-4 border cursor-pointer hover:shadow-sm transition-all text-center space-y-1 ${colorClass} ${severityFilter === sev ? 'ring-1 ring-slate-400' : ''}`}
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
          <Search className="absolute left-2.5 top-3 h-4 w-4 text-slate-400" />
          <Input 
            placeholder="Search IPs or SNI..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-9 bg-white border-slate-200 text-xs text-slate-800 focus-visible:ring-slate-300"
          />
        </div>
        <div className="flex gap-2 w-full md:w-auto">
          {['ALL', 'Critical', 'High', 'Medium', 'Low'].map(sev => (
            <Button
              key={sev}
              size="sm"
              variant={severityFilter === sev ? 'default' : 'outline'}
              onClick={() => setSeverityFilter(sev)}
              className="text-[10px] font-medium"
            >
              {sev}
            </Button>
          ))}
        </div>
      </div>

      {/* Tabular Alerts list */}
      <Card className="border border-slate-200 bg-white overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs mono">
            <thead>
              <tr className="bg-slate-50 border-b border-slate-200 text-slate-500 uppercase text-[9px] tracking-wider font-semibold">
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Source Socket</th>
                <th className="py-3 px-4">Destination Socket</th>
                <th className="py-3 px-4">SNI / Target Host</th>
                <th className="py-3 px-4">Risk Index</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {filteredAlerts.length > 0 ? (
                filteredAlerts.map(alert => {
                  const dateStr = alert.timestamp ? new Date(alert.timestamp * 1000).toLocaleString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', month: 'short', day: '2-digit' }) : 'N/A';
                  return (
                    <tr 
                      key={alert.flow_id}
                      onClick={() => handleSelectAlert(alert.flow_id)}
                      className={`hover:bg-slate-50/50 transition-colors cursor-pointer ${selectedAlertId === alert.flow_id ? 'bg-slate-50' : ''}`}
                    >
                      <td className="py-3.5 px-4 text-slate-500">{dateStr}</td>
                      <td className="py-3.5 px-4 font-semibold text-slate-800">{alert.src_ip}:{alert.src_port}</td>
                      <td className="py-3.5 px-4 font-semibold text-slate-800">{alert.dst_ip}:{alert.dst_port}</td>
                      <td className="py-3.5 px-4 text-indigo-600 font-medium truncate max-w-[150px]">{alert.sni || 'N/A'}</td>
                      <td className="py-3.5 px-4 text-red-600 font-bold">{alert.risk_score}/100</td>
                      <td className="py-3.5 px-4">
                        <Badge variant={alert.severity.toLowerCase()}>{alert.severity}</Badge>
                      </td>
                      <td className="py-3.5 px-4 text-right space-x-2" onClick={e => e.stopPropagation()}>
                        <Button 
                          size="sm" 
                          variant="outline" 
                          onClick={() => handleSelectAlert(alert.flow_id)}
                          className="h-7 px-2.5 text-[10px] border-slate-200 bg-white hover:bg-slate-50 text-slate-700"
                        >
                          Inspect
                        </Button>
                        <Button 
                          size="sm" 
                          className="h-7 px-2.5 text-[10px] bg-emerald-600 hover:bg-emerald-700 text-white font-medium"
                          onClick={(e) => handleAllowAlert(e, alert.flow_id)}
                          disabled={allowLoading}
                        >
                          Allow
                        </Button>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={7} className="text-center py-20 text-xs text-slate-400 uppercase tracking-wider font-medium">
                    No active threat alerts detected.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Threat Detail Slide-over Inspector Drawer */}
      <AnimatePresence>
        {selectedAlertId && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 bg-black/30 backdrop-blur-xs flex justify-end"
            onClick={() => setSelectedAlertId(null)}
          >
            <motion.div
              initial={{ x: '100%' }}
              animate={{ x: 0 }}
              exit={{ x: '100%' }}
              transition={{ type: 'spring', damping: 25, stiffness: 200 }}
              className="w-full max-w-xl bg-white border-l border-slate-200 h-full p-6 overflow-y-auto space-y-6 shadow-xl"
              onClick={e => e.stopPropagation()}
            >
              {loadingDetails ? (
                <div className="h-full flex flex-col items-center justify-center space-y-3 py-40">
                  <Loader2 className="w-8 h-8 text-slate-800 animate-spin" />
                  <span className="text-xs text-slate-400">Retrieving Forensic Telemetry...</span>
                </div>
              ) : alertDetails ? (
                <div className="space-y-6">
                  {/* Drawer Header */}
                  <div className="flex items-start justify-between border-b border-slate-200 pb-4">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <Badge variant={alertDetails.severity.toLowerCase()}>{alertDetails.severity}</Badge>
                        <Badge variant="outline" className="border-slate-200 text-slate-700 text-[9px] uppercase font-bold mono">{alertDetails.attack_category || 'Threat'}</Badge>
                        <span className="text-[10px] mono text-slate-400 uppercase">{new Date(alertDetails.timestamp * 1000).toLocaleString()}</span>
                      </div>
                      <h3 className="text-base font-bold text-slate-900 mono">{alertDetails.flow_id}</h3>
                    </div>
                    <Button size="icon" variant="ghost" onClick={() => setSelectedAlertId(null)} className="h-8 w-8 text-slate-400 hover:text-slate-800">
                      <X className="w-4 h-4" />
                    </Button>
                  </div>

                  {/* Summary Metric Callouts */}
                  <div className="grid grid-cols-2 gap-4">
                    <div className="p-4 rounded-xl border border-red-100 bg-red-50/30">
                      <div className="text-[9px] font-bold text-red-600 uppercase tracking-wider mono">Calculated Risk Index</div>
                      <div className="text-3xl font-black text-red-600 mt-1 mono">{alertDetails.risk_score}<span className="text-xs font-normal opacity-70">/100</span></div>
                    </div>
                    <div className="p-4 rounded-xl border border-slate-200 bg-slate-50/50">
                      <div className="text-[9px] font-bold text-slate-600 uppercase tracking-wider mono">ML Detection Confidence</div>
                      <div className="text-3xl font-black text-slate-800 mt-1 mono">{alertDetails.confidence}%</div>
                    </div>
                  </div>

                  {/* Sockets Details */}
                  <div className="space-y-2">
                    <h4 className="text-[9px] uppercase font-bold text-slate-400 tracking-widest">Network Context</h4>
                    <div className="grid grid-cols-2 gap-4 text-[10px] mono bg-slate-50 border border-slate-200 p-3 rounded-lg">
                      <div className="space-y-0.5">
                        <span className="text-slate-400 text-[8px] uppercase">Src Socket</span>
                        <div className="text-slate-800 font-bold">{alertDetails.src_ip}:{alertDetails.src_port}</div>
                      </div>
                      <div className="space-y-0.5">
                        <span className="text-slate-400 text-[8px] uppercase">Dst Socket</span>
                        <div className="text-slate-800 font-bold">{alertDetails.dst_ip}:{alertDetails.dst_port}</div>
                      </div>
                      <div className="col-span-2 space-y-0.5">
                        <span className="text-slate-400 text-[8px] uppercase">TLS Target Server (SNI)</span>
                        <div className="text-indigo-600 font-bold">{alertDetails.sni || 'N/A'}</div>
                      </div>
                    </div>
                  </div>

                  {/* Reputation threat intelligence */}
                  <div className="space-y-2">
                    <h4 className="text-[9px] uppercase font-bold text-slate-400 tracking-widest">Threat Intelligence & Anomaly Analysis</h4>
                    <div className="grid grid-cols-4 gap-2 text-center text-[10px] mono">
                      <div className="p-3 border border-slate-200 bg-slate-50 rounded-lg">
                        <div className="text-[8px] text-slate-400 uppercase">IP score</div>
                        <div className="text-sm font-black text-red-600 mt-1">{alertDetails.ip_reputation_score || 0}%</div>
                      </div>
                      <div className="p-3 border border-slate-200 bg-slate-50 rounded-lg">
                        <div className="text-[8px] text-slate-400 uppercase">Domain reputation</div>
                        <div className="text-sm font-black text-red-600 mt-1">{alertDetails.domain_reputation_score || 0}%</div>
                      </div>
                      <div className="p-3 border border-slate-200 bg-slate-50 rounded-lg">
                        <div className="text-[8px] text-slate-400 uppercase">Cert risk</div>
                        <div className="text-sm font-black text-amber-600 mt-1">{alertDetails.tls_risk_score || 0}/100</div>
                      </div>
                      <div className="p-3 border border-slate-200 bg-slate-50 rounded-lg">
                        <div className="text-[8px] text-slate-400 uppercase">Zero-Day Anomaly</div>
                        <div className={`text-sm font-black mt-1 ${alertDetails.anomaly_score > 60 ? 'text-red-600' : 'text-slate-800'}`}>{alertDetails.anomaly_score || 0}%</div>
                      </div>
                    </div>
                    
                    {alertDetails.ja3_match && (
                      <div className="p-3 border border-red-200 bg-red-50/50 rounded-lg text-[10px] mono text-red-700 leading-tight flex items-start gap-2 mt-2">
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
                      <h4 className="text-[9px] uppercase font-bold text-slate-400 tracking-widest">Forensic Explainer (SHAP)</h4>
                      <div className="space-y-2.5">
                        {alertDetails.top_features.map((feat, idx) => (
                          <div key={idx} className="space-y-1">
                            <div className="flex justify-between text-[9px] mono uppercase font-bold text-slate-500">
                              <span className="truncate max-w-[240px]">{feat.feature}</span>
                              <span>{(feat.importance).toFixed(4)}</span>
                            </div>
                            <div className="h-1.5 w-full bg-slate-100 rounded-full overflow-hidden">
                              <div 
                                className="h-full rounded-full bg-red-500" 
                                style={{ width: `${Math.min(100, feat.importance * 200)}%` }} 
                              />
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Whitelist / Allow threat drawer action */}
                  <Separator className="bg-slate-200" />
                  <div className="flex gap-3 justify-end pt-2">
                    <Button 
                      variant="outline" 
                      onClick={() => setSelectedAlertId(null)}
                      className="text-xs"
                    >
                      Cancel
                    </Button>
                    <Button 
                      onClick={() => handleAllowAlert(null, alertDetails.flow_id)}
                      disabled={allowLoading}
                      className="bg-emerald-600 hover:bg-emerald-700 text-white font-medium text-xs gap-1.5"
                    >
                      <ShieldCheck className="w-4 h-4" /> Allow & Whitelist Connection
                    </Button>
                  </div>
                </div>
              ) : (
                <div className="text-center py-20 text-xs text-slate-400">
                   forensic logs unavailable.
                </div>
              )}
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
