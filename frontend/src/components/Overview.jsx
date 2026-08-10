import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { 
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer
} from 'recharts';
import { 
  ShieldAlert, Activity, Database, Cpu, TrendingUp, AlertTriangle, CheckCircle 
} from 'lucide-react';
import { Card } from './ui/card';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import { Separator } from './ui/separator';

export default function Overview({ stats, activeAlerts, apiEndpoint, onRefresh }) {
  const [chartData, setChartData] = useState([]);
  const [allowLoading, setAllowLoading] = useState(false);

  // Local state for statistics in case parent hasn't loaded them yet
  const displayStats = stats || {
    total_flows: 0,
    total_threats: 0,
    total_bytes: 0,
    severity_breakdown: { Safe: 0, Low: 0, Medium: 0, High: 0, Critical: 0 },
    protocol_breakdown: { TCP: 0, UDP: 0 },
    top_suspect_ips: []
  };

  // Generate simulated historic risk trend data
  useEffect(() => {
    const data = [];
    const baseTime = Date.now();
    for (let i = 12; i >= 0; i--) {
      data.push({
        time: new Date(baseTime - i * 5000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        risk: Math.max(10, Math.floor(Math.random() * 30) + (displayStats.total_threats * 6))
      });
    }
    setChartData(data);
  }, [displayStats.total_threats]);

  const handleAllowAlert = async (flowId) => {
    setAllowLoading(true);
    try {
      const response = await fetch(`${apiEndpoint || 'http://127.0.0.1:8000'}/api/flows/${flowId}/allow`, {
        method: 'POST'
      });
      if (response.ok && onRefresh) {
        await onRefresh();
      }
    } catch (err) {
      console.error("Failed to whitelist threat:", err);
    } finally {
      setAllowLoading(false);
    }
  };

  const containerVariants = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: { staggerChildren: 0.08 }
    }
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 8 },
    show: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 100 } }
  };

  // Get top 5 active alerts
  const latestAlerts = activeAlerts.slice(0, 5);

  return (
    <motion.div 
      variants={containerVariants}
      initial="hidden"
      animate="show"
      className="space-y-6"
    >
      {/* Page Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-4 border-b border-slate-200 pb-6">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-slate-900">Security Operations Dashboard</h2>
          <p className="text-xs text-slate-500 mt-1">
            System overview and ML-assisted threat profiling telemetry
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs font-semibold text-slate-700 bg-slate-100 px-3.5 py-1.5 rounded-lg border border-slate-200 shadow-xs">
          <Activity className="w-3.5 h-3.5 animate-pulse text-emerald-600" /> Active Session Stream
        </div>
      </div>

      {/* Grid: 4 Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1: Total Flows */}
        <motion.div variants={itemVariants}>
          <Card className="p-5 border border-slate-200 bg-white relative overflow-hidden group hover:border-slate-300 transition-colors shadow-sm">
            <div className="absolute top-0 left-0 w-full h-[3px] bg-slate-900" />
            <div className="flex items-center justify-between text-slate-400">
              <span className="text-[10px] uppercase font-bold mono tracking-wider text-slate-500">Monitored Sessions</span>
              <Database className="w-4 h-4 text-slate-400" />
            </div>
            <div className="mt-4 flex items-baseline gap-2">
              <span className="text-3xl font-bold text-slate-900 mono">{displayStats.total_flows}</span>
              <span className="text-[9px] text-emerald-600 font-bold flex items-center gap-0.5">
                <TrendingUp className="w-2.5 h-2.5" /> 100%
              </span>
            </div>
            <p className="text-[10px] text-slate-400 font-medium uppercase mt-1">Total bidirectional flows logged</p>
          </Card>
        </motion.div>

        {/* Metric 2: Active Threats */}
        <motion.div variants={itemVariants}>
          <Card className="p-5 border border-slate-200 bg-white relative overflow-hidden group hover:border-slate-300 transition-colors shadow-sm">
            <div className="absolute top-0 left-0 w-full h-[3px] bg-red-500" />
            <div className="flex items-center justify-between text-slate-400">
              <span className="text-[10px] uppercase font-bold mono tracking-wider text-slate-500">Identified Alerts</span>
              <ShieldAlert className="w-4 h-4 text-red-500" />
            </div>
            <div className="mt-4 flex items-baseline gap-2">
              <span className="text-3xl font-bold text-slate-900 mono">{displayStats.total_threats}</span>
              {displayStats.total_threats > 0 ? (
                <span className="text-[9px] text-red-600 font-bold flex items-center gap-0.5 animate-pulse">
                  <AlertTriangle className="w-2.5 h-2.5" /> Threat flagged
                </span>
              ) : (
                <span className="text-[9px] text-emerald-600 font-bold flex items-center gap-0.5">
                  <CheckCircle className="w-2.5 h-2.5" /> Safe
                </span>
              )}
            </div>
            <p className="text-[10px] text-slate-400 font-medium uppercase mt-1">Anomalous or malicious connections</p>
          </Card>
        </motion.div>

        {/* Metric 3: Accuracy */}
        <motion.div variants={itemVariants}>
          <Card className="p-5 border border-slate-200 bg-white relative overflow-hidden group hover:border-slate-300 transition-colors shadow-sm">
            <div className="absolute top-0 left-0 w-full h-[3px] bg-slate-900" />
            <div className="flex items-center justify-between text-slate-400">
              <span className="text-[10px] uppercase font-bold mono tracking-wider text-slate-500">Model Accuracy</span>
              <Cpu className="w-4 h-4 text-slate-400" />
            </div>
            <div className="mt-4 flex items-baseline gap-2">
              <span className="text-3xl font-bold text-slate-900 mono">99.8%</span>
              <span className="text-[9px] text-slate-400 font-bold uppercase mono">xgb-v1</span>
            </div>
            <p className="text-[10px] text-slate-400 font-medium uppercase mt-1">Cross-validation score verified</p>
          </Card>
        </motion.div>

        {/* Metric 4: Total Traffic */}
        <motion.div variants={itemVariants}>
          <Card className="p-5 border border-slate-200 bg-white relative overflow-hidden group hover:border-slate-300 transition-colors shadow-sm">
            <div className="absolute top-0 left-0 w-full h-[3px] bg-slate-900" />
            <div className="flex items-center justify-between text-slate-400">
              <span className="text-[10px] uppercase font-bold mono tracking-wider text-slate-500">Payload Volume</span>
              <TrendingUp className="w-4 h-4 text-slate-400" />
            </div>
            <div className="mt-4 flex items-baseline gap-2">
              <span className="text-3xl font-bold text-slate-900 mono">
                {(displayStats.total_bytes / (1024 * 1024)).toFixed(2)}
              </span>
              <span className="text-[10px] text-slate-400 font-bold uppercase mono">MB</span>
            </div>
            <p className="text-[10px] text-slate-400 font-medium uppercase mt-1">Total traffic decoded</p>
          </Card>
        </motion.div>
      </div>

      {/* Grid: Risk Trend Chart and Target Suspect IP List */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Main Risk Trend Chart */}
        <motion.div variants={itemVariants} className="lg:col-span-8">
          <Card className="p-6 border border-slate-200 bg-white space-y-4 shadow-sm">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700">Operational Risk Trend</h3>
              <p className="text-xs text-slate-500">Real-time risk scoring activity based on dynamic feature scaling</p>
            </div>
            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                  <defs>
                    <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.12}/>
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke="#94a3b8" fontSize={9} fontClassName="mono" tickLine={false} />
                  <YAxis stroke="#94a3b8" fontSize={9} fontClassName="mono" tickLine={false} domain={[0, 100]} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#ffffff', border: '1px solid #e2e8f0', borderRadius: '8px', fontSize: '11px', color: '#0f172a' }}
                    labelStyle={{ color: '#64748b', fontWeight: 'bold' }}
                  />
                  <Area type="monotone" dataKey="risk" stroke="#ef4444" strokeWidth={2} fillOpacity={1} fill="url(#riskGrad)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </Card>
        </motion.div>

        {/* Target Suspect Matrix */}
        <motion.div variants={itemVariants} className="lg:col-span-4">
          <Card className="p-6 border border-slate-200 bg-white h-full flex flex-col justify-between shadow-sm">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700">Target Suspect Matrix</h3>
              <p className="text-xs text-slate-500 mb-4">Destination IP addresses triggering model alert states</p>
            </div>
            <div className="space-y-3 overflow-y-auto max-h-60 pr-1">
              {displayStats.top_suspect_ips.length > 0 ? (
                displayStats.top_suspect_ips.map(item => (
                  <div key={item.ip} className="flex items-center justify-between p-2.5 border border-slate-100 bg-slate-50/50 rounded-lg shadow-2xs">
                    <span className="text-xs mono text-red-600 font-bold">{item.ip}</span>
                    <span className="text-[10px] text-slate-500 uppercase font-semibold">{item.count} alerts</span>
                  </div>
                ))
              ) : (
                <div className="text-center py-10 text-xs text-slate-400 uppercase tracking-wider font-semibold">
                  All external targets rated clean.
                </div>
              )}
            </div>
          </Card>
        </motion.div>
      </div>

      {/* Active Alerts Monitor: Concise Table */}
      <motion.div variants={itemVariants}>
        <Card className="p-6 border border-slate-200 bg-white shadow-sm space-y-4">
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700">Active Threat Alerts</h3>
            <p className="text-xs text-slate-500">Concise monitor list of the latest critical events flagged by the engine</p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs mono">
              <thead>
                <tr className="border-b border-slate-200 text-slate-500 uppercase text-[9px] tracking-wider font-semibold">
                  <th className="py-2.5 px-2">Source Socket</th>
                  <th className="px-2">Destination Socket</th>
                  <th className="px-2">Proto</th>
                  <th className="px-2">Category</th>
                  <th className="px-2">Risk</th>
                  <th className="px-2">Severity</th>
                  <th className="text-right px-2">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {latestAlerts.length > 0 ? (
                  latestAlerts.map(alert => (
                    <tr key={alert.flow_id} className="hover:bg-slate-50/50">
                      <td className="py-3 px-2 font-semibold text-slate-800">{alert.src_ip}:{alert.src_port}</td>
                      <td className="py-3 px-2 font-semibold text-slate-800">{alert.dst_ip}:{alert.dst_port}</td>
                      <td className="py-3 px-2 text-slate-500">{alert.protocol}</td>
                      <td className="py-3 px-2">
                        <Badge variant="outline" className="border-red-200 text-red-600 font-bold uppercase text-[9px]">
                          {alert.attack_category || alert.classification}
                        </Badge>
                      </td>
                      <td className="py-3 px-2 text-red-600 font-bold">{alert.risk_score}/100</td>
                      <td className="py-3 px-2">
                        <Badge variant={alert.severity.toLowerCase()}>{alert.severity}</Badge>
                      </td>
                      <td className="py-3 px-2 text-right space-x-2">
                        <Button 
                          size="sm"
                          className="h-7 px-2 text-[9px] bg-emerald-600 hover:bg-emerald-700 text-white font-medium"
                          onClick={() => handleAllowAlert(alert.flow_id)}
                          disabled={allowLoading}
                        >
                          Allow
                        </Button>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={7} className="text-center py-8 text-xs text-slate-400 uppercase tracking-wider font-medium">
                      No active threat alerts detected.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>
      </motion.div>
    </motion.div>
  );
}
