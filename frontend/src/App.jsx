import React, { useState } from 'react';
import { cn } from '@/lib/utils';
import Upload from './components/Upload';
import ResultsSummary from './components/ResultsSummary';
import FlowTable from './components/FlowTable';
import TerminalLog from './components/TerminalLog';
import CombatRadar from './components/CombatRadar';
import { Button } from './components/ui/button';
import { Separator } from './components/ui/separator';
import { 
  Shield, 
  RefreshCcw, 
  Github, 
  Globe, 
  Terminal as TerminalIcon, 
  Zap, 
  Database, 
  LayoutDashboard, 
  Search, 
  Settings, 
  Activity,
  Cpu
} from 'lucide-react';

function NavButton({ children, active, onClick }) {
  return (
    <button 
      onClick={onClick}
      className={cn(
        "px-4 py-1.5 rounded text-[11px] font-bold uppercase tracking-tight transition-all flex items-center gap-2",
        active ? "text-primary bg-primary/5 shadow-[inset_0_0_10px_rgba(0,242,255,0.1)]" : "text-muted-foreground hover:text-slate-200"
      )}
    >
      {children}
    </button>
  );
}

function SideIcon({ icon: Icon, active }) {
  return (
    <div className={cn(
      "w-10 h-10 rounded-lg flex items-center justify-center transition-all cursor-pointer group",
      active ? "bg-primary text-black" : "text-muted-foreground hover:bg-white/5 hover:text-white"
    )}>
      <Icon className="w-5 h-5 transition-transform group-hover:scale-110" />
    </div>
  );
}

function StatusItem({ label, value, color }) {
  return (
    <div className="flex items-center justify-between text-[10px] mono">
      <span className="text-muted-foreground">{label}</span>
      <span className={cn("font-bold uppercase", color)}>{value}</span>
    </div>
  )
}

export default function App() {
  const [results, setResults] = useState(null);
  const [activeTab, setActiveTab] = useState('analyzer');

  const handleReset = () => setResults(null);

  return (
    <div className="min-h-screen bg-[#050505] text-slate-200 flex flex-col font-sans selection:bg-primary/30 overflow-hidden">
      <div className="scanline-overlay pointer-events-none fixed inset-0 z-[100] opacity-[0.03]" />
      
      {/* Top Navigation */}
      <header className="h-14 border-b border-white/5 bg-black/40 backdrop-blur-xl flex items-center justify-between px-6 z-50">
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-2 group cursor-pointer" onClick={handleReset}>
            <div className="bg-primary text-black p-1 rounded transition-all group-hover:scale-110 shadow-[0_0_15px_rgba(0,242,255,0.4)]">
              <Shield className="w-5 h-5 fill-current" />
            </div>
            <div className="flex flex-col leading-none">
              <span className="text-sm font-black tracking-tighter uppercase italic">Zenith</span>
              <span className="text-[9px] text-primary uppercase mono font-bold tracking-[0.2em]">Signal.Engine</span>
            </div>
          </div>
          
          <nav className="hidden lg:flex items-center gap-1">
            <NavButton active={activeTab === 'analyzer'} onClick={() => setActiveTab('analyzer')}>
               <Activity className="w-3.5 h-3.5" /> Analyzer
            </NavButton>
            <NavButton active={activeTab === 'telemetry'} onClick={() => setActiveTab('telemetry')}>
               <Zap className="w-3.5 h-3.5" /> Live Telemetry
            </NavButton>
            <NavButton active={activeTab === 'database'} onClick={() => setActiveTab('database')}>
               <Database className="w-3.5 h-3.5" /> Threat DB
            </NavButton>
          </nav>
        </div>

        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 px-3 py-1 bg-white/5 rounded-full border border-white/10 text-[10px] mono font-bold text-muted-foreground uppercase shadow-inner">
             <div className="flex items-center gap-1.5 animate-pulse">
               <Cpu className="w-3 h-3 text-primary" />
               <span>Zenith.Alpha</span>
             </div>
          </div>
        </div>
      </header>

      <div className="flex-1 flex overflow-hidden">
        {/* Sidebar Mini */}
        <aside className="w-16 border-r border-white/5 bg-black/20 flex flex-col items-center py-6 gap-6">
          <SideIcon icon={LayoutDashboard} active />
          <SideIcon icon={TerminalIcon} />
        </aside>

        {/* Main Dashboard Area */}
        <main className="flex-1 overflow-y-auto bg-gradient-to-br from-black via-[#050505] to-[#0a0a0a] relative custom-scrollbar p-6">
          {!results ? (
            <div className="max-w-4xl mx-auto h-full flex flex-col items-center justify-center space-y-12 animate-in fade-in duration-700">
               <div className="relative mb-8 text-center space-y-4">
                  <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary/10 border border-primary/20 text-primary text-[10px] font-bold uppercase tracking-widest animate-pulse">
                    <Shield className="w-3 h-3" /> System Ready
                  </div>
                  <h1 className="text-6xl font-black tracking-tighter text-white uppercase italic leading-none drop-shadow-2xl">
                    Deep Traffic <br/><span className="text-primary underline decoration-primary/20">Perception</span>
                  </h1>
                  <p className="text-muted-foreground mono text-xs uppercase tracking-[0.2em] max-w-lg mx-auto leading-relaxed">
                    XGBoost v1.0.4 Encrypted Content Analysis Engine. Automated Threat Detection for SSL/TLS Payloads.
                  </p>
               </div>

               <Upload onUploadSuccess={setResults} />
               
               <div className="grid grid-cols-1 md:grid-cols-2 gap-4 w-full max-w-3xl mt-12">
                  <TerminalLog results={null} />
                  <div className="border border-white/5 rounded-lg bg-card/20 p-6 flex flex-col justify-center space-y-2">
                     <div className="text-[10px] font-black uppercase text-primary tracking-widest">Protocol Support</div>
                     <div className="flex flex-wrap gap-2 pt-2">
                        {['TLS 1.3', 'QUIC', 'HTTP/3', 'SSH', 'PCAP-NG'].map(p => (
                          <span key={p} className="text-[9px] mono bg-white/5 border border-white/10 px-2 py-0.5 rounded text-muted-foreground">{p}</span>
                        ))}
                     </div>
                  </div>
               </div>
            </div>
          ) : (
            <div className="max-w-[1600px] mx-auto space-y-8 animate-in slide-in-from-bottom-4 duration-500">
              <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-6 border-b border-white/5 pb-8">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-benign animate-pulse" />
                    <span className="text-[10px] font-mono font-bold uppercase text-muted-foreground">Operation: Zenith-Gamma</span>
                  </div>
                  <h1 className="text-4xl font-black tracking-tighter text-white uppercase italic">Intercept Report</h1>
                  <p className="text-muted-foreground mono text-[10px] uppercase font-bold">Trace ID: <span className="text-primary">{results.job_id}</span> • PCAP_BUFFER_ALLOC_OK</p>
                </div>
                <div className="flex items-center gap-3">
                  <Button variant="outline" onClick={handleReset} className="border-white/5 hover:bg-white/5 uppercase mono text-[10px] font-bold">
                    <RefreshCcw className="w-3.5 h-3.5 mr-2" /> Reset Engine
                  </Button>
                  <Button className="bg-primary text-black hover:bg-primary/90 uppercase mono text-[10px] font-bold px-6 shadow-[0_0_20px_rgba(0,242,255,0.3)]">
                    Export JSON
                  </Button>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
                <div className="lg:col-span-8 flex flex-col gap-6">
                   <ResultsSummary results={results} />
                   <div className="flex-1">
                      <FlowTable data={results.results} />
                   </div>
                </div>
                
                <div className="lg:col-span-4 flex flex-col gap-6 min-h-full">
                  <CombatRadar results={results} />
                  <TerminalLog results={results} />
                  <div className="border border-white/5 rounded-lg p-6 bg-gradient-to-br from-card/20 to-transparent space-y-4">
                     <div className="text-[10px] font-bold uppercase text-muted-foreground tracking-widest flex items-center justify-between">
                        <span>Engine Status</span>
                        <span className="text-benign">99.8% Accuracy</span>
                     </div>
                     <Separator className="bg-white/5" />
                     <div className="space-y-3">
                        <StatusItem label="XGBoost Kernels" value="Active" color="text-benign" />
                        <StatusItem label="Entropy Calib" value="Verified" color="text-benign" />
                        <StatusItem label="Threat DB Sync" value="Local-v4" color="text-primary" />
                     </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </main>
      </div>

      {/* Global Command Bar (Mock) */}
      <div className="h-8 border-t border-white/5 bg-black/60 backdrop-blur px-4 flex items-center justify-between pointer-events-none">
        <div className="flex items-center gap-4 text-[9px] mono font-bold uppercase text-muted-foreground">
          <div className="flex items-center gap-1.5"><Activity className="w-2.5 h-2.5" /> Running: 10452-AF</div>
          <div className="flex items-center gap-1.5"><TerminalIcon className="w-2.5 h-2.5" /> Shell: zenith-v1</div>
        </div>
        <div className="text-[9px] mono text-primary">ROOT ACCESS GRANTED // READY TO INGEST</div>
      </div>
    </div>
  );
}
