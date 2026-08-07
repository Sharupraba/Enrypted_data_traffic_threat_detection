import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  FileText, Download, Calendar, Database, ShieldAlert, Cpu, 
  ExternalLink, Printer, CheckCircle, Clock, RefreshCw, Loader2
} from 'lucide-react';
import { Card } from './ui/card';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import { Separator } from './ui/separator';

export default function Reports({ apiEndpoint }) {
  const [downloading, setDownloading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [reportFlows, setReportFlows] = useState([]);
  const [reportAlerts, setReportAlerts] = useState([]);
  const [reportLogs, setReportLogs] = useState([
    { id: '1', date: 'Jul 04, 2026 00:10', type: 'CSV Export', status: 'SUCCESS' },
    { id: '2', date: 'Jul 03, 2026 18:42', type: 'JSON Dump', status: 'SUCCESS' },
    { id: '3', date: 'Jul 03, 2026 12:15', type: 'HTML Executive Report', status: 'SUCCESS' }
  ]);

  const fetchReportData = async () => {
    try {
      setLoading(true);
      const [flowsRes, alertsRes] = await Promise.all([
        fetch(`${apiEndpoint}/api/flows?limit=100`),
        fetch(`${apiEndpoint}/api/alerts?limit=100`)
      ]);
      if (flowsRes.ok) setReportFlows(await flowsRes.json());
      if (alertsRes.ok) setReportAlerts(await alertsRes.json());
    } catch (err) {
      console.error("Failed to load report data:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReportData();
  }, [apiEndpoint]);

  const triggerDownload = async (path, filename) => {
    try {
      setDownloading(true);
      const res = await fetch(`${apiEndpoint}/api/${path}`);
      if (!res.ok) throw new Error('Failed to generate report file.');
      
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.style.display = 'none';
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      const nowStr = new Date().toLocaleString([], { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
      const reportType = filename.endsWith('json') ? 'JSON Dump' : filename.endsWith('cef') ? 'CEF Export' : filename.endsWith('log') ? 'Syslog Export' : 'CSV Export';
      
      setReportLogs(prev => [
        { id: String(Date.now()), date: nowStr, type: reportType, status: 'SUCCESS' },
        ...prev
      ]);
    } catch (err) {
      console.error(err);
      alert('Failed to download report file: ' + err.message);
    } finally {
      setDownloading(false);
    }
  };

  const handlePrintHTML = () => {
    window.open(`${apiEndpoint}/api/reports/html`, '_blank');
  };

  const totalFlows = reportFlows.length;
  const totalAlerts = reportAlerts.length;
  const criticalCount = reportAlerts.filter(a => a.severity === 'Critical').length;

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-4 border-b border-slate-200 pb-6">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-slate-900">Security Reporting Center</h2>
          <p className="text-xs text-slate-500 mt-1">
            Generate executive compliance summaries, SIEM exports, and forensic datasets
          </p>
        </div>
        <Button onClick={fetchReportData} variant="outline" className="border-slate-200 bg-white hover:bg-slate-50 text-xs font-medium">
          <RefreshCw className="w-3 mr-2 text-slate-500" /> Sync Report Data
        </Button>
      </div>

      {/* Report Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="p-4 border border-slate-200 bg-white shadow-sm">
          <div className="text-[9px] font-bold text-slate-400 uppercase tracking-wider mono">Monitored Sessions</div>
          <div className="text-2xl font-bold text-slate-900 mt-1 mono">{totalFlows} <span className="text-xs text-slate-500 font-normal">records</span></div>
        </Card>
        <Card className="p-4 border border-red-200 bg-red-50/20 shadow-sm">
          <div className="text-[9px] font-bold text-red-600 uppercase tracking-wider mono">Threat Alerts Logged</div>
          <div className="text-2xl font-bold text-red-600 mt-1 mono">{totalAlerts} <span className="text-xs opacity-70 font-normal">detections</span></div>
        </Card>
        <Card className="p-4 border border-red-200 bg-red-50/20 shadow-sm">
          <div className="text-[9px] font-bold text-red-600 uppercase tracking-wider mono">Critical Threats</div>
          <div className="text-2xl font-bold text-red-600 mt-1 mono">{criticalCount} <span className="text-xs opacity-70 font-normal">critical</span></div>
        </Card>
      </div>

      {/* Export Action Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        {/* Export Formats */}
        <Card className="p-6 border border-slate-200 bg-white space-y-5 relative overflow-hidden shadow-sm">
          <div className="flex items-center gap-2 text-slate-800">
            <Database className="w-4 h-4 text-slate-500" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700">Spreadsheet Datasets</h3>
          </div>
          <p className="text-[10px] text-slate-500 leading-relaxed">
            Download flat datasets mapping all captured flows, flag configurations, and ML classification metrics.
          </p>
          <Separator className="bg-slate-100" />
          <div className="flex flex-col gap-3">
            <Button 
              onClick={() => triggerDownload('reports/csv', 'zenith_flow_report.csv')} 
              disabled={downloading}
              className="bg-white border border-slate-200 hover:bg-slate-50 text-slate-800 text-[10px] font-medium"
            >
              <Download className="w-3.5 h-3.5 mr-2 text-slate-500" /> Download CSV Dataset
            </Button>
            <Button 
              onClick={() => triggerDownload('reports/json', 'zenith_flow_report.json')}
              disabled={downloading}
              className="bg-white border border-slate-200 hover:bg-slate-50 text-slate-800 text-[10px] font-medium"
            >
              <Download className="w-3.5 h-3.5 mr-2 text-slate-500" /> Download JSON Dump
            </Button>
          </div>
        </Card>

        {/* SIEM Enterprise Exports */}
        <Card className="p-6 border border-slate-200 bg-white space-y-5 relative overflow-hidden shadow-sm">
          <div className="flex items-center gap-2 text-slate-800">
            <ShieldAlert className="w-4 h-4 text-slate-500" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700">SIEM Integration</h3>
          </div>
          <p className="text-[10px] text-slate-500 leading-relaxed">
            Export structured log files for Splunk, Microsoft Sentinel, ArcSight, and QRadar log ingestion.
          </p>
          <Separator className="bg-slate-100" />
          <div className="flex flex-col gap-3">
            <Button 
              onClick={() => triggerDownload('reports/cef', 'zenith_alerts.cef')} 
              disabled={downloading}
              className="bg-white border border-slate-200 hover:bg-slate-50 text-slate-800 text-[10px] font-medium"
            >
              <Download className="w-3.5 h-3.5 mr-2 text-slate-500" /> Export CEF (ArcSight)
            </Button>
            <Button 
              onClick={() => triggerDownload('reports/syslog', 'zenith_syslog.log')}
              disabled={downloading}
              className="bg-white border border-slate-200 hover:bg-slate-50 text-slate-800 text-[10px] font-medium"
            >
              <Download className="w-3.5 h-3.5 mr-2 text-slate-500" /> Export Syslog (RFC 5424)
            </Button>
          </div>
        </Card>

        {/* Executive Printing */}
        <Card className="p-6 border border-slate-200 bg-white space-y-5 relative overflow-hidden shadow-sm">
          <div className="flex items-center gap-2 text-slate-800">
            <FileText className="w-4 h-4 text-slate-500" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700">Executive Summary</h3>
          </div>
          <p className="text-[10px] text-slate-500 leading-relaxed">
            Generate styled SOC print-outs listing threat distribution stats and specific details of critical alerts.
          </p>
          <Separator className="bg-slate-100" />
          <Button 
            onClick={handlePrintHTML}
            className="w-full bg-slate-900 hover:bg-slate-800 text-white font-medium text-xs gap-1.5"
          >
            <Printer className="w-3.5 h-3.5" /> Open HTML Print Panel <ExternalLink className="w-3 h-3" />
          </Button>
        </Card>

        {/* History / Audit Log */}
        <Card className="p-6 border border-slate-200 bg-white space-y-5 relative overflow-hidden shadow-sm">
          <div className="flex items-center gap-2 text-slate-800">
            <Clock className="w-4 h-4 text-slate-500" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700">Export Audit Log</h3>
          </div>
          <div className="space-y-3 max-h-48 overflow-y-auto pr-1">
            {reportLogs.map(log => (
              <div key={log.id} className="flex justify-between items-center text-[10px] mono p-2 border border-slate-100 bg-slate-50/50 rounded-lg">
                <div className="space-y-0.5">
                  <div className="font-semibold text-slate-700">{log.type}</div>
                  <div className="text-[8px] text-slate-400">{log.date}</div>
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
