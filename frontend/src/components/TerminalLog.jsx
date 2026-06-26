import React, { useState, useEffect, useRef } from 'react';
import { Terminal as TerminalIcon, ShieldCheck, Activity } from 'lucide-react';
import { cn } from '@/lib/utils';

export default function TerminalLog({ results }) {
  const [logs, setLogs] = useState([
    { id: 1, type: 'info', msg: 'System initialized. Zenith Engine v1.0.4' },
    { id: 2, type: 'info', msg: 'Listening for PCAP ingestion...' },
  ]);
  const scrollRef = useRef(null);

  useEffect(() => {
    if (results) {
      const newLogs = [
        { id: Date.now(), type: 'success', msg: `PCAP Ingested: ${results.total_flows} flows identified.` },
        { id: Date.now()+1, type: 'warning', msg: `Running XGBoost classification on encrypted payloads...` },
        ...(results.threat_count > 0 ? [
          { id: Date.now()+2, type: 'error', msg: `CRITICAL: ${results.threat_count} potential security threats detected.` }
        ] : [
          { id: Date.now()+2, type: 'success', msg: `Clean Bill of Health: No malicious patterns detected.` }
        ])
      ];
      setLogs(prev => [...prev, ...newLogs]);
    }
  }, [results]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  return (
    <div className="bg-black/90 border border-primary/20 rounded-lg overflow-hidden font-mono text-[10px] h-48 flex flex-col shadow-2xl">
      <div className="bg-secondary/50 px-3 py-1 flex items-center justify-between border-b border-white/5">
        <div className="flex items-center gap-2">
          <TerminalIcon className="w-3 h-3 text-primary" />
          <span className="uppercase tracking-tighter font-bold text-white/50">System Logs</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-1.5 h-1.5 rounded-full bg-threat animate-pulse" />
          <span className="text-[8px] text-muted-foreground uppercase mono">Kernel v0.4.2</span>
        </div>
      </div>
      <div ref={scrollRef} className="p-3 overflow-y-auto space-y-1 custom-scrollbar">
        {logs.map((log) => (
          <div key={log.id} className="flex gap-2">
            <span className="text-white/20">[{new Date().toLocaleTimeString()}]</span>
            <span className={cn(
               log.type === 'info' && 'text-primary',
               log.type === 'success' && 'text-benign',
               log.type === 'warning' && 'text-yellow-400',
               log.type === 'error' && 'text-threat font-bold',
            )}>
              {log.type.toUpperCase()}: {log.msg}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
