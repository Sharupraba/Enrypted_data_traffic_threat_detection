import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { 
  FileText, Download, Calendar, Database, ShieldAlert, Cpu, 
  ExternalLink, Printer, CheckCircle, Clock
} from 'lucide-react';
import { Card } from './ui/card';
import { Button } from './ui/button';
import { Separator } from './ui/separator';

export default function Reports({ apiEndpoint }) {
  const [downloading, setDownloading] = useState(false);
  const [reportLogs, setReportLogs] = useState([
    { id: '1', date: 'Jul 04, 2026 00:10', type: 'CSV Export', status: 'SUCCESS' },
    { id: '2', date: 'Jul 03, 2026 18:42', type: 'JSON Dump', status: 'SUCCESS' },
    { id: '3', date: 'Jul 03, 2026 12:15', type: 'HTML Executive Report', status: 'SUCCESS' }
  ]);

  const triggerDownload = (path, filename) => {
    setDownloading(true);
    const link = document.createElement('a');
    link.href = `${apiEndpoint}/api/${path}`;
    link.setAttribute('download', filename);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    // Add to local audit logs list
    setTimeout(() => {
      const nowStr = new Date().toLocaleString([], { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
      setReportLogs(prev => [
        { id: String(Date.now()), date: nowStr, type: filename.endsWith('json') ? 'JSON Dump' : 'CSV Export', status: 'SUCCESS' },
        ...prev
      ]);
      setDownloading(false);
    }, 1000);
  };

  const handlePrintHTML = () => {
    window.open(`${apiEndpoint}/api/reports/html`, '_blank');
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex justify-between items-end border-b border-white/5 pb-6">
        <div>
          <h2 className="text-2xl font-black tracking-tight text-white uppercase italic">Security Reporting Center</h2>
          <p className="text-[10px] text-muted-foreground uppercase mono tracking-[0.15em] mt-1">
            Generate executive compliance summaries and structured spreadsheet exports
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Export Formats */}
        <Card className="p-6 border border-white/5 bg-black/40 space-y-5 relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-primary/20 to-transparent" />
          <div className="flex items-center gap-2 text-primary">
            <Database className="w-4 h-4" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">Spreadsheet Exports</h3>
          </div>
          <p className="text-[10px] text-muted-foreground leading-relaxed">
            Download flat datasets mapping all captured flows, flag configurations, and ML classification metrics.
          </p>
          <Separator className="bg-white/5" />
          <div className="flex flex-col gap-3">
            <Button 
              onClick={() => triggerDownload('reports/csv', 'zenith_flow_report.csv')} 
              disabled={downloading}
              className="bg-white/5 border border-white/10 hover:bg-white/10 text-slate-200 uppercase mono text-[9px] font-bold"
            >
              <Download className="w-3.5 h-3.5 mr-2" /> Download CSV Dataset
            </Button>
            <Button 
              onClick={() => triggerDownload('reports/json', 'zenith_flow_report.json')}
              disabled={downloading}
              className="bg-white/5 border border-white/10 hover:bg-white/10 text-slate-200 uppercase mono text-[9px] font-bold"
            >
              <Download className="w-3.5 h-3.5 mr-2" /> Download JSON Dump
            </Button>
          </div>
        </Card>

        {/* Executive Printing */}
        <Card className="p-6 border border-white/5 bg-black/40 space-y-5 relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-primary/20 to-transparent" />
          <div className="flex items-center gap-2 text-primary">
            <FileText className="w-4 h-4" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">Executive Summary</h3>
          </div>
          <p className="text-[10px] text-muted-foreground leading-relaxed">
            Generate styled SOC print-outs listing threat distribution stats and specific details of critical alerts.
          </p>
          <Separator className="bg-white/5" />
          <Button 
            onClick={handlePrintHTML}
            className="w-full bg-primary text-black hover:bg-primary/95 font-bold uppercase mono text-[9px] tracking-widest shadow-[0_0_15px_rgba(0,242,255,0.2)]"
          >
            <Printer className="w-3.5 h-3.5 mr-2" /> Open HTML Print Panel <ExternalLink className="w-3 h-3 ml-1.5" />
          </Button>
        </Card>

        {/* History / Audit Log */}
        <Card className="p-6 border border-white/5 bg-black/40 space-y-5 relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-primary/20 to-transparent" />
          <div className="flex items-center gap-2 text-primary">
            <Clock className="w-4 h-4" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">Export Audit Log</h3>
          </div>
          <div className="space-y-3 max-h-48 overflow-y-auto pr-1">
            {reportLogs.map(log => (
              <div key={log.id} className="flex justify-between items-center text-[10px] mono p-2 border border-white/5 bg-white/[0.01] rounded-lg">
                <div className="space-y-0.5">
                  <div className="font-semibold text-slate-300">{log.type}</div>
                  <div className="text-[8px] text-muted-foreground">{log.date}</div>
                </div>
                <Badge variant="benign">{log.status}</Badge>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}
