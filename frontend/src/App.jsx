import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { cn } from '@/lib/utils';
import { 
  Shield, Database, Cpu, Activity, LayoutDashboard, Radio, 
  ShieldAlert, TableProperties, Search, BarChart3, FileSpreadsheet,
  LogOut, Bell, Settings, Terminal, ShieldCheck, Info, X
} from 'lucide-react';
import { Separator } from './components/ui/separator';

import Auth from './components/Auth';
import Overview from './components/Overview';
import LiveTelemetry from './components/LiveTelemetry';
import PCAPAnalysis from './components/PCAPAnalysis';
import ThreatAlerts from './components/ThreatAlerts';
import FlowExplorer from './components/FlowExplorer';
import ThreatIntel from './components/ThreatIntel';
import Analytics from './components/Analytics';
import Reports from './components/Reports';

function SideNavButton({ icon: Icon, label, active, onClick }) {
  return (
    <button 
      onClick={onClick}
      className={cn(
        "w-full px-4 py-2.5 rounded-xl text-[10px] font-black uppercase tracking-wider transition-all flex items-center gap-3 text-left border",
        active 
          ? "text-primary bg-primary/5 border-primary/20 shadow-[inset_0_0_10px_rgba(0,242,255,0.05)]" 
          : "text-muted-foreground border-transparent hover:text-slate-200 hover:bg-white/[0.02]"
      )}
    >
      <Icon className={cn("w-4 h-4 shrink-0", active ? "text-primary" : "text-muted-foreground/80")} />
      <span>{label}</span>
    </button>
  );
}

export default function App() {
  const [accessGranted, setAccessGranted] = useState(true);
  const [apiEndpoint, setApiEndpoint] = useState('http://127.0.0.1:8000');
  const [activeTab, setActiveTab] = useState('overview');
  
  // SOC data states
  const [flows, setFlows] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState(null);
  
  // Real-time notifications queue
  const [toasts, setToasts] = useState([]);
  const [isConnected, setIsConnected] = useState(false);
  const socketRef = useRef(null);

  // Authenticate portal
  const handleLoginSuccess = (endpoint) => {
    setApiEndpoint(endpoint);
    setAccessGranted(true);
  };

  // Sync historical and diagnostic metrics from SQLite
  const handleSyncData = async () => {
    try {
      const statsRes = await fetch(`${apiEndpoint}/api/analytics/stats`);
      const flowsRes = await fetch(`${apiEndpoint}/api/flows?limit=1000`);
      const alertsRes = await fetch(`${apiEndpoint}/api/alerts?limit=1000`);

      if (statsRes.ok) setStats(await statsRes.json());
      if (flowsRes.ok) setFlows(await flowsRes.json());
      if (alertsRes.ok) setAlerts(await alertsRes.json());
    } catch (err) {
      console.error("Data synchronization failed:", err);
    }
  };

  // Connect WebSocket channel for real-time broadcasts
  useEffect(() => {
    if (!accessGranted) return;

    // Initial sync
    handleSyncData();

    const wsUrl = apiEndpoint.replace('http', 'ws') + '/ws';
    const socket = new WebSocket(wsUrl);
    socketRef.current = socket;

    socket.onopen = () => setIsConnected(true);
    socket.onclose = () => setIsConnected(false);
    socket.onerror = () => setIsConnected(false);

    socket.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.event === 'new_flow') {
          // Update local flows list
          setFlows(prev => [msg.data, ...prev].slice(0, 1000));
          // Refresh statistics
          handleSyncData();
        } else if (msg.event === 'new_alert') {
          // Append to alerts registry
          setAlerts(prev => [msg.data, ...prev]);
          // Add custom animated alert toast notification
          const toastId = Date.now();
          setToasts(prev => [...prev, { id: toastId, ...msg.data }]);
          // Auto-cleanup toast after 6s
          setTimeout(() => {
            setToasts(prev => prev.filter(t => t.id !== toastId));
          }, 6000);
        }
      } catch (err) {
        console.error(err);
      }
    };

    return () => {
      socket.close();
    };
  }, [accessGranted, apiEndpoint]);

  if (!accessGranted) {
    return <Auth onLoginSuccess={handleLoginSuccess} />;
  }

  return (
    <div className="min-h-screen bg-[#050505] text-slate-200 flex flex-col font-sans selection:bg-primary/30 overflow-hidden relative">
      {/* Visual cyber mesh overlays */}
      <div className="scanline-overlay pointer-events-none fixed inset-0 z-[100] opacity-[0.015]" />
      
      {/* Top SOC Navigation Bar */}
      <header className="h-14 border-b border-white/5 bg-black/40 backdrop-blur-xl flex items-center justify-between px-6 z-50 shrink-0">
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-2.5">
            <div className="bg-primary text-black p-1 rounded-lg transition-transform hover:scale-105 shadow-[0_0_15px_rgba(0,242,255,0.3)]">
              <Shield className="w-5 h-5 fill-current" />
            </div>
            <div className="flex flex-col leading-none">
              <span className="text-sm font-black tracking-tighter uppercase italic text-white">Zenith SOC</span>
              <span className="text-[8px] text-primary uppercase mono font-bold tracking-[0.25em] mt-0.5">Packet.Dissect</span>
            </div>
          </div>
        </div>

        {/* Global Connection & Info Status */}
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 px-3 py-1 bg-white/5 rounded-full border border-white/10 text-[9px] mono font-bold text-muted-foreground uppercase shadow-inner">
             <div className="flex items-center gap-1.5">
               {isConnected ? (
                 <ShieldCheck className="w-3.5 h-3.5 text-benign animate-pulse" />
               ) : (
                 <ShieldAlert className="w-3.5 h-3.5 text-threat animate-pulse" />
               )}
               <span>{isConnected ? "SOC Pipeline Active" : "SOC Engine Offline"}</span>
             </div>
          </div>
          <Bell className="w-4.5 h-4.5 text-muted-foreground hover:text-white cursor-pointer transition-colors" />
          <Settings className="w-4.5 h-4.5 text-muted-foreground hover:text-white cursor-pointer transition-colors" />
          <Separator orientation="vertical" className="h-5 bg-white/10" />
          <button 
            onClick={() => setAccessGranted(false)}
            className="p-1 rounded hover:bg-white/5 text-muted-foreground hover:text-threat transition-all"
            title="Log Out"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </header>

      {/* Workspace Panel */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left collapsable side menu */}
        <aside className="w-60 border-r border-white/5 bg-black/20 flex flex-col justify-between py-6 px-4 shrink-0">
          <div className="space-y-6">
            <div className="text-[9px] mono uppercase font-bold text-muted-foreground/60 tracking-[0.2em] px-2">Console Navigation</div>
            <div className="space-y-1.5">
              <SideNavButton icon={LayoutDashboard} label="Overview Dashboard" active={activeTab === 'overview'} onClick={() => setActiveTab('overview')} />
              <SideNavButton icon={Radio} label="Live Telemetry" active={activeTab === 'live'} onClick={() => setActiveTab('live')} />
              <SideNavButton icon={Terminal} label="PCAP Analysis" active={activeTab === 'pcap'} onClick={() => setActiveTab('pcap')} />
              <SideNavButton icon={ShieldAlert} label="Threat Alerts" active={activeTab === 'alerts'} onClick={() => setActiveTab('alerts')} />
              <SideNavButton icon={TableProperties} label="Flow Explorer" active={activeTab === 'explorer'} onClick={() => setActiveTab('explorer')} />
              <SideNavButton icon={Search} label="Threat Intel Search" active={activeTab === 'intel'} onClick={() => setActiveTab('intel')} />
              <SideNavButton icon={BarChart3} label="Model Analytics" active={activeTab === 'analytics'} onClick={() => setActiveTab('analytics')} />
              <SideNavButton icon={FileSpreadsheet} label="Reporting panel" active={activeTab === 'reports'} onClick={() => setActiveTab('reports')} />
            </div>
          </div>

          {/* Footer diagnostics widget */}
          <div className="p-3 border border-white/5 bg-white/[0.01] rounded-xl text-[9px] mono space-y-1 text-muted-foreground">
            <div className="flex justify-between">
              <span>Active NIC:</span>
              <span className="text-slate-300">eth0</span>
            </div>
            <div className="flex justify-between">
              <span>DB Size:</span>
              <span className="text-slate-300">{flows.length} rows</span>
            </div>
            <div className="flex justify-between">
              <span>Sync Rate:</span>
              <span className="text-benign">Stable</span>
            </div>
          </div>
        </aside>

        {/* Center operational view scrollable panel */}
        <main className="flex-1 overflow-y-auto bg-gradient-to-br from-black via-[#050505] to-[#0A0A0C] relative custom-scrollbar p-6">
          <AnimatePresence mode="wait">
            <motion.div
              key={activeTab}
              initial={{ opacity: 0, y: 5 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -5 }}
              transition={{ duration: 0.25 }}
              className="h-full"
            >
              {activeTab === 'overview' && <Overview stats={stats} activeAlerts={alerts} />}
              {activeTab === 'live' && <LiveTelemetry socketUrl={apiEndpoint} />}
              {activeTab === 'pcap' && <PCAPAnalysis apiEndpoint={apiEndpoint} onResultsAvailable={handleSyncData} />}
              {activeTab === 'alerts' && <ThreatAlerts apiEndpoint={apiEndpoint} alerts={alerts} onRefresh={handleSyncData} />}
              {activeTab === 'explorer' && <FlowExplorer data={flows} apiEndpoint={apiEndpoint} onRefresh={handleSyncData} />}
              {activeTab === 'intel' && <ThreatIntel apiEndpoint={apiEndpoint} />}
              {activeTab === 'analytics' && <Analytics />}
              {activeTab === 'reports' && <Reports apiEndpoint={apiEndpoint} />}
            </motion.div>
          </AnimatePresence>
        </main>
      </div>

      {/* Animated Floating Alerts / Toast Queue (Framer Motion) */}
      <div className="fixed bottom-6 right-6 z-[200] flex flex-col gap-3 w-80 pointer-events-none">
        <AnimatePresence>
          {toasts.map(toast => (
            <motion.div
              key={toast.id}
              initial={{ opacity: 0, y: 50, scale: 0.9 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, scale: 0.9 }}
              transition={{ type: 'spring', damping: 20 }}
              className="p-4 border border-threat/20 bg-[#0E0707] rounded-xl flex items-start gap-3 shadow-[0_10px_30px_rgba(0,0,0,0.5)] pointer-events-auto"
            >
              <ShieldAlert className="w-5 h-5 text-threat shrink-0 mt-0.5 animate-bounce" />
              <div className="flex-1 text-[10px] mono">
                <span className="text-threat font-black uppercase tracking-wider block">Critical Threat Alert</span>
                <p className="text-white font-medium mt-0.5 truncate">{toast.src_ip} → {toast.dst_ip}</p>
                <div className="flex justify-between items-center mt-2 pt-1 border-t border-white/5">
                  <span className="text-muted-foreground uppercase">Risk Index: <b>{toast.risk_score}</b></span>
                  <button 
                    onClick={() => setToasts(prev => prev.filter(t => t.id !== toast.id))}
                    className="text-muted-foreground hover:text-white"
                  >
                    Dismiss
                  </button>
                </div>
              </div>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </div>
  );
}
