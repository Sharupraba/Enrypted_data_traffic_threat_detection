import React, { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import { Upload as UploadIcon, File as FileIcon, X, Loader2, ShieldAlert, Cpu, Terminal } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Button } from './ui/button';
import { Card } from './ui/card';

export default function Upload({ onUploadSuccess }) {
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState(null);

  const onDrop = useCallback((acceptedFiles) => {
    setFile(acceptedFiles[0]);
    setError(null);
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

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('http://localhost:8000/api/upload', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.detail || 'Upload failed');
      }

      const results = await response.json();
      onUploadSuccess(results);
    } catch (err) {
      console.error(err);
      setError(err.message);
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="w-full space-y-6 animate-in fade-in zoom-in-95 duration-500">
      <Card className={cn(
        "relative group cursor-pointer transition-all duration-500 border border-white/5 bg-black/40 hover:bg-black/60 overflow-hidden",
        isDragActive ? "border-primary shadow-[0_0_30px_rgba(0,242,255,0.2)]" : "hover:border-primary/30",
        file && "border-primary/50"
      )} {...getRootProps()}>
        <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-primary/20 to-transparent" />
        <input {...getInputProps()} />
        
        <div className="px-12 py-16 flex flex-col items-center justify-center space-y-6">
          <div className={cn(
            "w-20 h-20 rounded-2xl flex items-center justify-center border transition-all duration-500 shadow-2xl",
            isDragActive ? "bg-primary text-black border-primary rotate-12 scale-110" : "bg-white/5 border-white/10 text-primary group-hover:border-primary/40"
          )}>
            {file ? <FileIcon className="w-10 h-10" /> : <UploadIcon className="w-10 h-10" />}
          </div>
          
          <div className="text-center space-y-2">
            {file ? (
              <div className="space-y-1">
                <p className="text-lg font-black text-white italic uppercase tracking-tighter">{file.name}</p>
                <div className="flex items-center justify-center gap-2 text-[10px] mono text-primary font-bold uppercase tracking-widest">
                   <Cpu className="w-3 h-3" /> {(file.size / (1024 * 1024)).toFixed(2)} MB • READY_FOR_SCAN
                </div>
              </div>
            ) : (
              <div className="space-y-1">
                <p className="text-sm font-bold text-slate-400 uppercase tracking-widest">
                  {isDragActive ? "Release to scan" : "Drop PCAP here"}
                </p>
                <p className="text-[10px] text-muted-foreground mono font-bold uppercase tracking-tighter opacity-50">.pcap / .pcapng • max 100mb</p>
              </div>
            )}
          </div>
        </div>
      </Card>

      {error && (
        <div className="border border-threat/20 bg-threat/5 text-threat p-4 rounded-lg flex items-start gap-3 animate-in shake-1 duration-300">
          <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5" />
          <div className="text-[11px] font-bold uppercase mono leading-tight">
            <p>Scanning Interrupted</p>
            <p className="opacity-70 mt-1">{error}</p>
          </div>
        </div>
      )}

      <div className="flex flex-col sm:flex-row gap-4 items-center justify-center">
        {file && (
          <Button variant="ghost" onClick={(e) => {
            e.stopPropagation();
            setFile(null);
          }} disabled={uploading} className="uppercase mono text-[10px] font-bold text-muted-foreground hover:text-threat">
            <X className="w-4 h-4 mr-2" /> Discard
          </Button>
        )}
        <Button 
          size="lg" 
          className={cn(
            "min-w-64 uppercase mono text-[11px] font-black tracking-[0.2em] transition-all",
            file && !uploading && "bg-primary text-black hover:bg-primary/80 shadow-[0_0_30px_rgba(0,242,255,0.4)]"
          )}
          disabled={!file || uploading}
          onClick={(e) => {
            e.stopPropagation();
            handleUpload();
          }}
        >
          {uploading ? (
            <div className="flex items-center gap-3">
              <Loader2 className="w-4 h-4 animate-spin" />
              <span>Analyzing Payloads...</span>
            </div>
          ) : (
            <div className="flex items-center gap-2">
               <Terminal className="w-4 h-4" /> Start Decoding
            </div>
          )}
        </Button>
      </div>
    </div>
  );
}
