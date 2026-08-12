import React, { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Upload as UploadIcon, File as FileIcon, X, Loader2, ShieldAlert, Cpu, 
  Terminal, ShieldCheck, Database, CheckCircle, ArrowRight 
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { Button } from './ui/button';
import { Card } from './ui/card';
import { Badge } from './ui/badge';
import { Separator } from './ui/separator';

export default function PCAPAnalysis({ apiEndpoint, onResultsAvailable }) {
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [progressStep, setProgressStep] = useState(0);
  const [error, setError] = useState(null);
  const [scanSummary, setScanSummary] = useState(null);

  const steps = [
    "Uploading binary packets...",
    "Reconstructing bidirectional flows...",
    "Extracting TCP, Timing, TLS & DNS features...",
    "Running XGBoost predictive classification...",
    "Enriching threats with reputation intelligence..."
  ];

  const onDrop = useCallback((acceptedFiles) => {
    setFile(acceptedFiles[0]);
    setError(null);
    setScanSummary(null);
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/vnd.tcpdump.pcap': ['.pcap'],
      'application/x-pcapng': ['.pcapng'],
    },
    multiple: false,
  });

  const handleUpload = async () => {
    if (!file) return;

    setUploading(true);
    setError(null);
    setProgressStep(0);

    // Simulate stepping through pipeline steps for premium feel
    const stepInterval = setInterval(() => {
      setProgressStep(prev => {
        if (prev < steps.length - 1) return prev + 1;
        return prev;
      });
    }, 1500);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch(`${apiEndpoint}/api/upload`, {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.detail || 'Upload failed');
      }

      const results = await response.json();
      clearInterval(stepInterval);
      setProgressStep(steps.length - 1);
      
      // Delay slightly for presentation of completion
      setTimeout(() => {
        setScanSummary(results);
        if (onResultsAvailable) {
          onResultsAvailable(results);
        }
        setUploading(false);
      }, 800);

    } catch (err) {
      clearInterval(stepInterval);
      console.error(err);
      setError(err.message);
      setUploading(false);
    }
  };

  const handleReset = () => {
    setFile(null);
    setScanSummary(null);
    setError(null);
  };

  return (
    <div className="space-y-6">
      {/* Header controls panel */}
      <div className="flex justify-between items-end border-b border-slate-200 pb-6">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-slate-900">Offline PCAP Analysis</h2>
          <p className="text-xs text-slate-500 mt-1">
            Ingest and batch decode packet capture recordings
          </p>
        </div>
      </div>

      <div className="max-w-4xl mx-auto">
        {!scanSummary ? (
          <div className="space-y-6">
            <Card className={cn(
              "relative group cursor-pointer transition-all duration-350 border bg-white overflow-hidden shadow-sm",
              isDragActive ? "border-slate-400 bg-slate-50" : "border-slate-200 hover:border-slate-300",
              file && "border-slate-400"
            )} {...getRootProps()}>
              <input {...getInputProps()} />
              
              <div className="px-12 py-20 flex flex-col items-center justify-center space-y-6">
                <div className={cn(
                  "w-16 h-16 rounded-2xl flex items-center justify-center border transition-all duration-350 shadow-xs",
                  isDragActive ? "bg-slate-900 text-white border-slate-900" : "bg-slate-50 border-slate-200 text-slate-700"
                )}>
                  {file ? <FileIcon className="w-8 h-8" /> : <UploadIcon className="w-8 h-8" />}
                </div>
                
                <div className="text-center space-y-2">
                  {file ? (
                    <div className="space-y-1">
                      <p className="text-sm font-bold text-slate-800 mono">{file.name}</p>
                      <div className="flex items-center justify-center gap-2 text-[10px] mono text-indigo-600 font-bold uppercase tracking-wider">
                         <Cpu className="w-3.5 h-3.5" /> {(file.size / (1024 * 1024)).toFixed(2)} MB • Ingestion Ready
                      </div>
                    </div>
                  ) : (
                    <div className="space-y-1">
                      <p className="text-xs font-bold text-slate-600 uppercase tracking-wider">
                        {isDragActive ? "Drop binary capture here" : "Drag and drop network capture file"}
                      </p>
                      <p className="text-[9px] text-slate-400 mono font-bold uppercase tracking-tight opacity-70">
                        Supports .pcap / .pcapng files up to 100MB
                      </p>
                    </div>
                  )}
                </div>
              </div>
            </Card>

            {uploading && (
              <Card className="p-6 border border-slate-200 bg-white space-y-4 shadow-sm">
                <div className="flex items-center gap-3">
                  <Loader2 className="w-4 h-4 text-slate-800 animate-spin" />
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-700">Deconstructing Binary</span>
                </div>
                
                {/* Step indicator */}
                <div className="space-y-2.5">
                  {steps.map((step, idx) => {
                    const isPassed = idx < progressStep;
                    const isActive = idx === progressStep;
                    return (
                      <div key={idx} className="flex items-center gap-3 text-[10px] mono">
                        <div className={cn(
                          "w-4 h-4 rounded-full border flex items-center justify-center text-[8px] font-bold",
                          isPassed ? "bg-slate-900 border-slate-900 text-white" : 
                          isActive ? "border-slate-900 text-slate-900 animate-pulse" : "border-slate-200 text-slate-400"
                        )}>
                          {isPassed ? "✓" : idx + 1}
                        </div>
                        <span className={cn(
                          isPassed ? "text-slate-400 line-through opacity-60" : 
                          isActive ? "text-slate-900 font-bold" : "text-slate-400"
                        )}>{step}</span>
                      </div>
                    );
                  })}
                </div>
              </Card>
            )}

            {error && (
              <div className="border border-red-200 bg-red-50 text-red-700 p-4 rounded-xl flex items-start gap-3 animate-in shake-1 duration-300">
                <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5" />
                <div className="text-[10px] font-bold uppercase mono leading-tight">
                  <p>Deconstruction Interrupted</p>
                  <p className="opacity-70 mt-1">{error}</p>
                </div>
              </div>
            )}

            <div className="flex gap-4 items-center justify-center">
              {file && (
                <Button variant="ghost" onClick={handleReset} disabled={uploading} className="text-xs text-slate-500 hover:text-red-600">
                  <X className="w-4 h-4 mr-2" /> Discard
                </Button>
              )}
              <Button 
                size="lg" 
                className={cn(
                  "min-w-64 uppercase mono text-[10px] font-bold tracking-widest transition-all",
                  file && !uploading ? "bg-slate-900 hover:bg-slate-800 text-white shadow-xs" : "bg-slate-100 text-slate-400"
                )}
                disabled={!file || uploading}
                onClick={handleUpload}
              >
                Start Ingestion
              </Button>
            </div>
          </div>
        ) : (
          <motion.div 
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-6"
          >
            {/* Ingestion Report Dashboard */}
            <Card className="p-6 border border-slate-200 bg-white relative overflow-hidden shadow-sm">
              <div className="absolute top-0 left-0 w-full h-[3px] bg-slate-900" />
              <div className="flex justify-between items-start">
                <div className="space-y-1">
                  <div className="flex items-center gap-1.5 text-emerald-600 text-[10px] font-bold uppercase tracking-wider">
                    <ShieldCheck className="w-4 h-4" /> Trace Ingestion Complete
                  </div>
                  <h3 className="text-base font-bold text-slate-800 mono">{file?.name}</h3>
                  <p className="text-[9px] text-slate-400 uppercase mono mt-1">Ingestion Session Log Summary</p>
                </div>
                <Button onClick={handleReset} variant="outline" className="border-slate-200 bg-white hover:bg-slate-50 text-[10px] font-bold uppercase mono">
                  Reset Ingestor
                </Button>
              </div>

              <Separator className="bg-slate-200 my-6" />

              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="p-4 border border-slate-200 bg-slate-50 rounded-xl text-center space-y-1">
                  <div className="text-[10px] text-slate-500 uppercase font-bold mono">Flows Parsed</div>
                  <div className="text-3xl font-bold text-slate-800 mono">{scanSummary.total_flows}</div>
                </div>
                <div className="p-4 border border-red-200 bg-red-50/20 rounded-xl text-center space-y-1">
                  <div className="text-[10px] text-red-600 uppercase font-bold mono">Threats Flagged</div>
                  <div className="text-3xl font-bold text-red-600 mono">{scanSummary.threat_count}</div>
                </div>
                <div className="p-4 border border-slate-200 bg-slate-50 rounded-xl text-center space-y-1">
                  <div className="text-[10px] text-emerald-600 uppercase font-bold mono">Benign Count</div>
                  <div className="text-3xl font-bold text-emerald-600 mono">{scanSummary.benign_count}</div>
                </div>
              </div>

              {/* Show top 5 threats identified */}
              {scanSummary.threat_count > 0 && (
                <div className="mt-8 space-y-3">
                  <div className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Top Detected Alerts</div>
                  <div className="border border-slate-200 bg-white rounded-xl divide-y divide-slate-100 overflow-hidden">
                    {scanSummary.results.filter(r => (r.classification || r.prediction) === 'Threat').slice(0, 5).map((row, idx) => (
                      <div key={idx} className="p-3 bg-red-50/10 flex items-center justify-between text-[10px] mono">
                        <div className="flex items-center gap-4">
                          <span className="text-red-600 font-bold">ALERT #{idx + 1}</span>
                          <span className="font-medium text-slate-700">{row.src_ip}:{row.src_port} → {row.dst_ip}:{row.dst_port}</span>
                        </div>
                        <div className="flex items-center gap-3">
                          <span className="text-slate-500 truncate max-w-[120px]">{row.sni || 'N/A'}</span>
                          <Badge variant="threat">{row.confidence}% Confidence</Badge>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </Card>
          </motion.div>
        )}
      </div>
    </div>
  );
}
