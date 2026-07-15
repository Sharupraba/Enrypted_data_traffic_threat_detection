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
      <div className="flex justify-between items-end border-b border-white/5 pb-6">
        <div>
          <h2 className="text-2xl font-black tracking-tight text-white uppercase italic">Offline PCAP Analysis</h2>
          <p className="text-[10px] text-muted-foreground uppercase mono tracking-[0.15em] mt-1">
            Ingest and batch decode packet capture recordings
          </p>
        </div>
      </div>

      <div className="max-w-4xl mx-auto">
        {!scanSummary ? (
          <div className="space-y-6">
            <Card className={cn(
              "relative group cursor-pointer transition-all duration-500 border border-white/5 bg-black/40 hover:bg-black/60 overflow-hidden",
              isDragActive ? "border-primary shadow-[0_0_30px_rgba(0,242,255,0.15)]" : "hover:border-primary/20",
              file && "border-primary/40"
            )} {...getRootProps()}>
              <div className="absolute top-0 left-0 w-full h-[2px] bg-gradient-to-r from-transparent via-primary/20 to-transparent" />
              <input {...getInputProps()} />
              
              <div className="px-12 py-20 flex flex-col items-center justify-center space-y-6">
                <div className={cn(
                  "w-16 h-16 rounded-2xl flex items-center justify-center border transition-all duration-500 shadow-2xl",
                  isDragActive ? "bg-primary text-black border-primary rotate-6 scale-105" : "bg-white/5 border-white/10 text-primary group-hover:border-primary/30"
                )}>
                  {file ? <FileIcon className="w-8 h-8" /> : <UploadIcon className="w-8 h-8" />}
                </div>
                
                <div className="text-center space-y-2">
                  {file ? (
                    <div className="space-y-1">
                      <p className="text-base font-bold text-white italic uppercase tracking-tight">{file.name}</p>
                      <div className="flex items-center justify-center gap-2 text-[9px] mono text-primary font-bold uppercase tracking-wider">
                         <Cpu className="w-3 h-3" /> {(file.size / (1024 * 1024)).toFixed(2)} MB • READY_FOR_DECOMPOSITION
                      </div>
                    </div>
                  ) : (
                    <div className="space-y-1">
                      <p className="text-xs font-bold text-slate-400 uppercase tracking-widest">
                        {isDragActive ? "Drop binary capture here" : "Drag and drop network capture file"}
                      </p>
                      <p className="text-[9px] text-muted-foreground mono font-bold uppercase tracking-tight opacity-40">
                        Supports .pcap / .pcapng files up to 100MB
                      </p>
                    </div>
                  )}
                </div>
              </div>
            </Card>

            {uploading && (
              <Card className="p-6 border border-white/5 bg-black/40 space-y-4">
                <div className="flex items-center gap-3">
                  <Loader2 className="w-4 h-4 text-primary animate-spin" />
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-300">Deconstructing Binary</span>
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
                          isPassed ? "bg-primary border-primary text-black" : 
                          isActive ? "border-primary text-primary animate-pulse" : "border-white/10 text-muted-foreground"
                        )}>
                          {isPassed ? "✓" : idx + 1}
                        </div>
                        <span className={cn(
                          isPassed ? "text-slate-300 line-through opacity-50" : 
                          isActive ? "text-primary font-bold" : "text-muted-foreground"
                        )}>{step}</span>
                      </div>
                    );
                  })}
                </div>
              </Card>
            )}

            {error && (
              <div className="border border-threat/20 bg-threat/5 text-threat p-4 rounded-xl flex items-start gap-3 animate-in shake-1 duration-300">
                <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5" />
                <div className="text-[10px] font-bold uppercase mono leading-tight">
                  <p>Deconstruction Interrupted</p>
                  <p className="opacity-70 mt-1">{error}</p>
                </div>
              </div>
            )}

            <div className="flex gap-4 items-center justify-center">
              {file && (
                <Button variant="ghost" onClick={handleReset} disabled={uploading} className="uppercase mono text-[9px] font-bold text-muted-foreground hover:text-threat">
                  <X className="w-4 h-4 mr-2" /> Discard
                </Button>
              )}
              <Button 
                size="lg" 
                className={cn(
                  "min-w-64 uppercase mono text-[10px] font-black tracking-widest transition-all",
                  file && !uploading && "bg-primary text-black hover:bg-primary/80 shadow-[0_0_20px_rgba(0,242,255,0.3)]"
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
            <Card className="p-6 border border-white/5 bg-black/40 relative overflow-hidden">
              <div className="absolute top-0 left-0 w-full h-[3px] bg-gradient-to-r from-benign to-primary" />
              <div className="flex justify-between items-start">
                <div className="space-y-1">
                  <div className="flex items-center gap-1.5 text-benign text-[10px] font-bold uppercase tracking-wider">
                    <ShieldCheck className="w-4 h-4" /> Trace Scan Complete
                  </div>
                  <h3 className="text-lg font-black text-white uppercase italic">{file?.name}</h3>
                  <p className="text-[9px] text-muted-foreground uppercase mono mt-1">Ingestion Session Log Summary</p>
                </div>
                <Button onClick={handleReset} variant="outline" className="border-white/10 hover:bg-white/5 uppercase mono text-[9px] font-bold">
                  Reset Ingestor
                </Button>
              </div>

              <Separator className="bg-white/5 my-6" />

              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="p-4 border border-white/5 bg-white/[0.01] rounded-xl text-center space-y-1">
                  <div className="text-[10px] text-muted-foreground uppercase font-bold mono">Flows Parsed</div>
                  <div className="text-3xl font-black text-white">{scanSummary.total_flows}</div>
                </div>
                <div className="p-4 border border-white/5 bg-white/[0.01] rounded-xl text-center space-y-1">
                  <div className="text-[10px] text-muted-foreground uppercase font-bold mono">Threats Flagged</div>
                  <div className="text-3xl font-black text-threat animate-pulse">{scanSummary.threat_count}</div>
                </div>
                <div className="p-4 border border-white/5 bg-white/[0.01] rounded-xl text-center space-y-1">
                  <div className="text-[10px] text-muted-foreground uppercase font-bold mono">Benign Count</div>
                  <div className="text-3xl font-black text-benign">{scanSummary.benign_count}</div>
                </div>
              </div>

              {/* Show top 5 threats identified */}
              {scanSummary.threat_count > 0 && (
                <div className="mt-8 space-y-3">
                  <div className="text-[10px] uppercase font-bold text-muted-foreground tracking-wider">Top Detected Alerts</div>
                  <div className="border border-white/5 rounded-xl divide-y divide-white/5 overflow-hidden">
                    {scanSummary.results.filter(r => r.prediction === 'Threat').slice(0, 5).map((row, idx) => (
                      <div key={idx} className="p-3 bg-threat/[0.01] flex items-center justify-between text-[10px] mono">
                        <div className="flex items-center gap-4">
                          <span className="text-threat font-bold">ALERT #{idx + 1}</span>
                          <span className="font-medium text-slate-300">{row.src_ip}:{row.src_port} → {row.dst_ip}:{row.dst_port}</span>
                        </div>
                        <div className="flex items-center gap-3">
                          <span className="text-muted-foreground truncate max-w-[120px]">{row.sni || 'N/A'}</span>
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
