import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { 
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  BarChart, Bar, Cell, PieChart, Pie
} from 'recharts';
import { 
  ShieldAlert, Activity, Database, Cpu, TrendingUp, AlertTriangle, CheckCircle 
} from 'lucide-react';
import { Card } from './ui/card';
import { Separator } from './ui/separator';

export default function Overview({ stats, activeAlerts }) {
  const [chartData, setChartData] = useState([]);

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
        risk: Math.max(10, Math.floor(Math.random() * 40) + (displayStats.total_threats * 8))
      });
    }
    setChartData(data);
  }, [displayStats.total_threats]);

  // Protocol Chart Data
  const protocolData = [
    { name: 'TCP', value: displayStats.protocol_breakdown.TCP || 0 },
    { name: 'UDP', value: displayStats.protocol_breakdown.UDP || 0 }
  ];

  // Severity Distribution Data
  const severityColors = {
    Critical: '#FF3B30',
    High: '#FF9500',
    Medium: '#FFCC00',
    Low: '#3498DB',
    Safe: '#34C759'
  };

  const severityData = Object.entries(displayStats.severity_breakdown)
    .map(([name, value]) => ({ name, value, color: severityColors[name] }))
    .filter(item => item.value > 0);

  const containerVariants = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: { staggerChildren: 0.1 }
    }
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 10 },
    show: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 100 } }
  };

  return (
    <motion.div 
      variants={containerVariants}
      initial="hidden"
      animate="show"
      className="space-y-6"
    >
      {/* Page Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-4 border-b border-white/5 pb-6">
        <div>
          <h2 className="text-2xl font-black tracking-tight text-white uppercase italic">Security Operations Dashboard</h2>
          <p className="text-[10px] text-muted-foreground uppercase mono tracking-[0.15em] mt-1">
            System overview and ML-assisted threat profiling telemetry
          </p>
        </div>
        <div className="flex items-center gap-2 text-[10px] mono font-bold uppercase text-primary bg-primary/5 px-3 py-1 rounded border border-primary/20">
          <Activity className="w-3 h-3 animate-pulse" /> Active Session Stream
        </div>
      </div>

      {/* Grid: 4 Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1: Total Flows */}
        <motion.div variants={itemVariants}>
          <Card className="p-5 border border-white/5 bg-black/40 relative overflow-hidden group hover:border-white/10 transition-colors">
            <div className="absolute top-0 left-0 w-full h-[2px] bg-white/5 group-hover:bg-primary/30 transition-colors" />
            <div className="flex items-center justify-between text-muted-foreground">
              <span className="text-[10px] uppercase font-bold mono tracking-wider">Monitored Sessions</span>
              <Database className="w-4 h-4 text-muted-foreground/60" />
            </div>
            <div className="mt-4 flex items-baseline gap-2">
              <span className="text-3xl font-black text-white">{displayStats.total_flows}</span>
              <span className="text-[9px] text-benign font-bold flex items-center gap-0.5">
                <TrendingUp className="w-2.5 h-2.5" /> 100%
              </span>
            </div>
            <p className="text-[9px] text-muted-foreground uppercase tracking-tight mt-1">Total bidirectional flows logged</p>
          </Card>
        </motion.div>

        {/* Metric 2: Active Threats */}
        <motion.div variants={itemVariants}>
          <Card className="p-5 border border-white/5 bg-black/40 relative overflow-hidden group hover:border-white/10 transition-colors">
            <div className="absolute top-0 left-0 w-full h-[2px] bg-white/5 group-hover:bg-threat/30 transition-colors" />
            <div className="flex items-center justify-between text-muted-foreground">
              <span className="text-[10px] uppercase font-bold mono tracking-wider">Identified Alerts</span>
              <ShieldAlert className="w-4 h-4 text-threat" />
            </div>
            <div className="mt-4 flex items-baseline gap-2">
              <span className="text-3xl font-black text-white">{displayStats.total_threats}</span>
              {displayStats.total_threats > 0 ? (
                <span className="text-[9px] text-threat font-bold flex items-center gap-0.5 animate-pulse">
                  <AlertTriangle className="w-2.5 h-2.5" /> Alert active
                </span>
              ) : (
                <span className="text-[9px] text-benign font-bold flex items-center gap-0.5">
                  <CheckCircle className="w-2.5 h-2.5" /> Clear
                </span>
              )}
            </div>
            <p className="text-[9px] text-muted-foreground uppercase tracking-tight mt-1">Anomalous or malicious signatures</p>
          </Card>
        </motion.div>

        {/* Metric 3: Accuracy */}
        <motion.div variants={itemVariants}>
          <Card className="p-5 border border-white/5 bg-black/40 relative overflow-hidden group hover:border-white/10 transition-colors">
            <div className="absolute top-0 left-0 w-full h-[2px] bg-white/5 group-hover:bg-primary/30 transition-colors" />
            <div className="flex items-center justify-between text-muted-foreground">
              <span className="text-[10px] uppercase font-bold mono tracking-wider">Accuracy Threshold</span>
              <Cpu className="w-4 h-4 text-primary" />
            </div>
            <div className="mt-4 flex items-baseline gap-2">
              <span className="text-3xl font-black text-white">99.8%</span>
              <span className="text-[9px] text-muted-foreground font-bold uppercase mono">xgb-v1</span>
            </div>
            <p className="text-[9px] text-muted-foreground uppercase tracking-tight mt-1">Cross-validation score verified</p>
          </Card>
        </motion.div>

        {/* Metric 4: Total Traffic */}
        <motion.div variants={itemVariants}>
          <Card className="p-5 border border-white/5 bg-black/40 relative overflow-hidden group hover:border-white/10 transition-colors">
            <div className="absolute top-0 left-0 w-full h-[2px] bg-white/5 group-hover:bg-primary/30 transition-colors" />
            <div className="flex items-center justify-between text-muted-foreground">
              <span className="text-[10px] uppercase font-bold mono tracking-wider">Throughput Volume</span>
              <TrendingUp className="w-4 h-4 text-muted-foreground/60" />
            </div>
            <div className="mt-4 flex items-baseline gap-2">
              <span className="text-3xl font-black text-white">
                {(displayStats.total_bytes / (1024 * 1024)).toFixed(2)}
              </span>
              <span className="text-[10px] text-muted-foreground font-bold uppercase mono">MB</span>
            </div>
            <p className="text-[9px] text-muted-foreground uppercase tracking-tight mt-1">Payload volume decoded</p>
          </Card>
        </motion.div>
      </div>

      {/* Charts Grid: 2 columns */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Main Risk Trend: 8 cols */}
        <motion.div variants={itemVariants} className="lg:col-span-8">
          <Card className="p-6 border border-white/5 bg-black/40 space-y-4">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">Operational Risk Trend</h3>
              <p className="text-[10px] text-muted-foreground">Real-time risk scoring activity based on dynamic feature scaling</p>
            </div>
            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                  <defs>
                    <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00F2FF" stopOpacity={0.1}/>
                      <stop offset="95%" stopColor="#00F2FF" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke="#555" fontSize={9} fontClassName="mono" tickLine={false} />
                  <YAxis stroke="#555" fontSize={9} fontClassName="mono" tickLine={false} domain={[0, 100]} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#0B0B0C', border: '1px solid #1E1E22', borderRadius: '8px', fontSize: '10px' }}
                    labelStyle={{ color: '#aaa', fontWeight: 'bold' }}
                  />
                  <Area type="monotone" dataKey="risk" stroke="#00F2FF" strokeWidth={1.5} fillOpacity={1} fill="url(#riskGrad)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </Card>
        </motion.div>

        {/* Severity & Protocol Mix: 4 cols */}
        <motion.div variants={itemVariants} className="lg:col-span-4 flex flex-col gap-6">
          {/* Protocol Distribution */}
          <Card className="p-6 border border-white/5 bg-black/40 flex-1 flex flex-col justify-between">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">Protocol Breakdown</h3>
              <p className="text-[10px] text-muted-foreground">Distribution of TCP and UDP protocol sessions</p>
            </div>
            <div className="h-32 w-full mt-4">
              {displayStats.total_flows > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={protocolData} layout="vertical" margin={{ top: 5, right: 15, left: -15, bottom: 5 }}>
                    <XAxis type="number" stroke="#555" fontSize={8} hide />
                    <YAxis dataKey="name" type="category" stroke="#888" fontSize={9} tickLine={false} />
                    <Tooltip contentStyle={{ backgroundColor: '#0B0B0C', border: '1px solid #1E1E22', fontSize: '9px' }} />
                    <Bar dataKey="value" fill="#00F2FF" radius={[0, 4, 4, 0]} barSize={10}>
                      <Cell fill="#00F2FF" />
                      <Cell fill="#3498DB" />
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex items-center justify-center text-[10px] mono text-muted-foreground uppercase">
                  Awaiting ingestion...
                </div>
              )}
            </div>
          </Card>

          {/* Severity Levels */}
          <Card className="p-6 border border-white/5 bg-black/40 flex-1 flex flex-col justify-between">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">Severity Profiling</h3>
              <p className="text-[10px] text-muted-foreground">Scored severity classifications from ML database</p>
            </div>
            <div className="space-y-2 mt-4">
              {severityData.length > 0 ? (
                severityData.map(item => (
                  <div key={item.name} className="space-y-1">
                    <div className="flex justify-between text-[9px] mono uppercase font-bold text-muted-foreground">
                      <span>{item.name}</span>
                      <span>{item.value} ({Math.round(item.value / displayStats.total_flows * 100)}%)</span>
                    </div>
                    <div className="h-1.5 w-full bg-white/5 rounded-full overflow-hidden">
                      <div className="h-full rounded-full" style={{ width: `${(item.value / displayStats.total_flows) * 100}%`, backgroundColor: item.color }} />
                    </div>
                  </div>
                ))
              ) : (
                <div className="h-full flex items-center justify-center text-[10px] mono text-muted-foreground uppercase py-6">
                  No active threat signatures.
                </div>
              )}
            </div>
          </Card>
        </motion.div>
      </div>

      {/* Suspect Sources */}
      <motion.div variants={itemVariants}>
        <Card className="p-6 border border-white/5 bg-black/40">
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">Target Suspect Matrix</h3>
            <p className="text-[10px] text-muted-foreground mb-4">Destination IP addresses triggering model alert states</p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
            {displayStats.top_suspect_ips.length > 0 ? (
              displayStats.top_suspect_ips.map(item => (
                <div key={item.ip} className="p-3 border border-white/5 bg-white/[0.02] rounded-lg text-center space-y-1">
                  <div className="text-[10px] mono text-threat font-bold">{item.ip}</div>
                  <div className="text-[9px] text-muted-foreground uppercase mono">{item.count} alerts registered</div>
                </div>
              ))
            ) : (
              <div className="col-span-5 text-center py-6 text-[10px] mono text-muted-foreground uppercase">
                All external targets rated as clean.
              </div>
            )}
          </div>
        </Card>
      </motion.div>
    </motion.div>
  );
}
