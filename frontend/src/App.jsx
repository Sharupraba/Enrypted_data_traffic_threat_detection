import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { cn } from '@/lib/utils';
import { 
  Shield, Database, Cpu, Activity, LayoutDashboard, Radio, 
  ShieldAlert, TableProperties, Search, BarChart3, FileSpreadsheet,
    Bell, Settings as SettingsIcon, Terminal, ShieldCheck, Info, X
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
import Settings from './components/Settings';

function SideNavButton({ icon: Icon, label, active, onClick }) {
  return (
    <button 
      onClick={onClick}
      className={cn(
        "w-full px-4 py-2.5 rounded-xl text-[10px] font-bold uppercase tracking-wider transition-all flex items-center gap-3 text-left border",
        active 
          ? "text-slate-900 bg-white border-slate-200 shadow-sm" 
          : "text-slate-500 border-transparent hover:text-slate-900 hover:bg-slate-100/50"
      )}
    >
      <Icon className={cn("w-4 h-4 shrink-0", active ? "text-primary" : "text-slate-400")} />
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
  const [liveSessionFlows, setLiveSessionFlows] = useState([]);
  
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

  return (
    <div className="min-h-screen bg-white text-slate-900 flex flex-col font-sans selection:bg-primary/10 overflow-hidden relative">
      
      {/* Top SOC Navigation Bar */}
      <header className="h-14 border-b border-slate-200 bg-white flex items-center justify-between px-6 z-50 shrink-0">
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-2.5">
            <div className="bg-slate-900 text-white p-1.5 rounded-lg transition-transform hover:scale-105 shadow-sm">
              <Shield className="w-5 h-5 fill-current" />
            </div>
            <div className="flex flex-col leading-none">
              <span className="text-sm font-semibold tracking-tight text-slate-900">NetFlow Security Monitor</span>
              <span className="text-[8px] text-slate-500 uppercase mono font-bold tracking-[0.2em] mt-0.5">Packet Engine</span>
            </div>
          </div>
        </div>

        {/* Global Connection & Info Status */}
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 px-3 py-1 bg-slate-100 rounded-full border border-slate-200 text-[9px] mono font-bold text-slate-700 uppercase">
             <div className="flex items-center gap-1.5">
               {isConnected ? (
                 <ShieldCheck className="w-3.5 h-3.5 text-emerald-600 animate-pulse" />
               ) : (
                 <ShieldAlert className="w-3.5 h-3.5 text-rose-600 animate-pulse" />
               )}
               <span>{isConnected ? "Engine Active" : "Engine Offline"}</span>
             </div>
          </div>
          <Bell className="w-4 h-4 text-slate-500 hover:text-slate-900 cursor-pointer transition-colors" />
          <SettingsIcon 
            className={`w-4.5 h-4.5 cursor-pointer transition-colors ${activeTab === 'settings' ? 'text-slate-900' : 'text-slate-500 hover:text-slate-900'}`} 
            onClick={() => setActiveTab('settings')}
            title="System Settings"
          />
        </div>
      </header>

      {/* Workspace Panel */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left collapsable side menu */}
        <aside className="w-60 border-r border-slate-200 bg-slate-50 flex flex-col justify-between py-6 px-4 shrink-0">
          <div className="space-y-6">
            <div className="text-[9px] mono uppercase font-bold text-slate-500 tracking-[0.2em] px-2">Console Navigation</div>
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
          <div className="p-3 border border-slate-200 bg-white rounded-xl text-[9px] mono space-y-1 text-slate-500">
            <div className="flex justify-between">
              <span>Active NIC:</span>
              <span className="text-slate-800">eth0</span>
            </div>
            <div className="flex justify-between">
              <span>DB Size:</span>
              <span className="text-slate-800">{flows.length} rows</span>
            </div>
            <div className="flex justify-between">
              <span>Sync Rate:</span>
              <span className="text-emerald-600 font-bold">Stable</span>
            </div>
          </div>
        </aside>

        {/* Center operational view scrollable panel */}
        <main className="flex-1 overflow-y-auto bg-slate-50 relative custom-scrollbar p-6">
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
              {activeTab === 'live' && <LiveTelemetry socketUrl={apiEndpoint} sessionFlows={liveSessionFlows} setSessionFlows={setLiveSessionFlows} />}
              {activeTab === 'pcap' && <PCAPAnalysis apiEndpoint={apiEndpoint} onResultsAvailable={handleSyncData} />}
              {activeTab === 'alerts' && <ThreatAlerts apiEndpoint={apiEndpoint} alerts={alerts} onRefresh={handleSyncData} />}
              {activeTab === 'explorer' && <FlowExplorer data={flows} apiEndpoint={apiEndpoint} onRefresh={handleSyncData} />}
              {activeTab === 'intel' && <ThreatIntel apiEndpoint={apiEndpoint} />}
              {activeTab === 'analytics' && <Analytics />}
              {activeTab === 'reports' && <Reports apiEndpoint={apiEndpoint} />}
              {activeTab === 'settings' && <Settings apiEndpoint={apiEndpoint} />}
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
              className="p-4 border border-rose-200 bg-white rounded-xl flex items-start gap-3 shadow-lg pointer-events-auto"
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
