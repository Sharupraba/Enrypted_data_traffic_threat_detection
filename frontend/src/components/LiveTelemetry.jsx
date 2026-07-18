import React, { useEffect, useState, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Play, Square, Wifi, WifiOff, Cpu, Layers, AlertCircle, Eye, 
  ChevronRight, RefreshCw, Activity, Terminal
} from 'lucide-react';
import { Card } from './ui/card';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import { Separator } from './ui/separator';

export default function LiveTelemetry({ socketUrl }) {
  const [interfaces, setInterfaces] = useState([]);
  const [selectedInterface, setSelectedInterface] = useState('');
  const [isCapturing, setIsCapturing] = useState(false);
  const [isConnected, setIsConnected] = useState(false);
  const [flows, setFlows] = useState([]);
  const [selectedFlow, setSelectedFlow] = useState(null);
  const [loading, setLoading] = useState(false);

  const socketRef = useRef(null);

  // 1. Fetch available interfaces and check current capture status
  const fetchInterfacesAndStatus = async () => {
    setLoading(true);
    try {
      // Fetch interfaces
      const ifaceResponse = await fetch(`${socketUrl}/api/interfaces`);
      let ifaceList = [];
      if (ifaceResponse.ok) {
        ifaceList = await ifaceResponse.json();
        setInterfaces(ifaceList);
      }

      // Fetch running status
      const statusResponse = await fetch(`${socketUrl}/api/capture/status`);
      if (statusResponse.ok) {
        const statusData = await statusResponse.json();
        if (statusData.is_running) {
          setIsCapturing(true);
          setSelectedInterface(statusData.interface);
        } else if (ifaceList.length > 0) {
          setSelectedInterface(ifaceList[0].pcap_name || ifaceList[0].name);
        }
      } else if (ifaceList.length > 0) {
        setSelectedInterface(ifaceList[0].pcap_name || ifaceList[0].name);
      }
    } catch (err) {
      console.error("Failed to load interfaces or status:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchInterfacesAndStatus();
  }, [socketUrl]);

  // 2. Manage WebSocket connection
  useEffect(() => {
    const wsUrl = socketUrl.replace('http', 'ws') + '/ws';
    const socket = new WebSocket(wsUrl);
    socketRef.current = socket;

    socket.onopen = () => {
      setIsConnected(true);
    };

    socket.onclose = () => {
      setIsConnected(false);
    };

    socket.onerror = (err) => {
      console.error("WebSocket error:", err);
      setIsConnected(false);
    };

    socket.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.event === 'new_flow') {
          // Prepend new flow to the list and keep most recent 50 flows
          setFlows(prev => [msg.data, ...prev].slice(0, 50));
        }
      } catch (err) {
        console.error("Error parsing socket message:", err);
      }
    };

    return () => {
      socket.close();
    };
  }, [socketUrl]);

  // 3. Start/Stop Capture controls
  const handleStartCapture = async () => {
    if (!selectedInterface) return;
    setLoading(true);
    try {
      const response = await fetch(`${socketUrl}/api/capture/start?interface=${selectedInterface}`, {
        method: 'POST'
      });
      if (response.ok) {
        setIsCapturing(true);
      } else {
        const errData = await response.json();
        alert(errData.detail || "Failed to start capture");
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleStopCapture = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${socketUrl}/api/capture/stop`, {
        method: 'POST'
      });
      if (response.ok) {
        setIsCapturing(false);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header controls panel */}
      <div className="flex flex-col xl:flex-row justify-between items-start xl:items-center gap-6 border-b border-white/5 pb-6">
        <div>
          <h2 className="text-2xl font-black tracking-tight text-white uppercase italic">Live Interface Ingestion</h2>
          <p className="text-[10px] text-muted-foreground uppercase mono tracking-[0.15em] mt-1">
            Real-time decryption header sniffers and classification pipelines
          </p>
        </div>

        {/* Network controls */}
        <div className="flex flex-wrap items-center gap-4 bg-white/[0.02] border border-white/5 p-3 rounded-xl w-full xl:w-auto">
          {/* Status badge */}
          <div className="flex items-center gap-2 px-3 py-1 bg-black/40 rounded-lg border border-white/5 text-[9px] mono uppercase font-bold">
            {isConnected ? (
              <span className="text-benign flex items-center gap-1.5">
                <Wifi className="w-3.5 h-3.5 animate-pulse" /> WS Connected
              </span>
            ) : (
              <span className="text-threat flex items-center gap-1.5">
                <WifiOff className="w-3.5 h-3.5" /> Offline
              </span>
            )}
          </div>

          {/* Interface Selector */}
          <div className="flex items-center gap-2">
            <span className="text-[9px] mono uppercase font-bold text-muted-foreground">NIC:</span>
            <select
              value={selectedInterface}
              onChange={(e) => setSelectedInterface(e.target.value)}
              disabled={isCapturing || loading}
              className="bg-black/60 border border-white/10 text-[10px] px-3 py-1.5 rounded-lg text-slate-200 focus:outline-none focus:border-primary/50 cursor-pointer mono"
            >
              {interfaces.length > 0 ? (
                interfaces.map(iface => (
                  <option key={iface.name} value={iface.pcap_name || iface.name}>
                    {iface.description} ({iface.name})
                  </option>
                ))
              ) : (
                <option value="">No adapters found</option>
              )}
            </select>
          </div>

          <Button
            size="sm"
            onClick={fetchInterfacesAndStatus}
            disabled={isCapturing || loading}
            variant="ghost"
            className="p-2 border border-white/10 text-muted-foreground hover:text-white hover:bg-white/5"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </Button>

          {/* Action triggers */}
          {isCapturing ? (
            <Button
              size="sm"
              onClick={handleStopCapture}
              disabled={loading}
              className="bg-threat text-white hover:bg-threat/80 uppercase mono text-[9px] font-black tracking-widest px-4 shadow-[0_0_15px_rgba(255,59,48,0.2)]"
            >
              <Square className="w-3 h-3 mr-2 fill-current" /> Terminate Capture
            </Button>
          ) : (
            <Button
              size="sm"
              onClick={handleStartCapture}
              disabled={loading || !selectedInterface}
              className="bg-primary text-black hover:bg-primary/90 uppercase mono text-[9px] font-black tracking-widest px-4 shadow-[0_0_15px_rgba(0,242,255,0.2)]"
            >
              <Play className="w-3 h-3 mr-2 fill-current" /> Initialize Capture
            </Button>
          )}
        </div>
      </div>

      {/* Main split display: 8 cols table / 4 cols drilldown */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        <Card className="lg:col-span-8 p-6 border border-white/5 bg-black/40 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">Live Traffic Feed</h3>
              <p className="text-[10px] text-muted-foreground">Rolling list of the 50 most recent analyzed bidirectional flows</p>
            </div>
            <div className="text-[9px] mono text-muted-foreground uppercase bg-white/5 px-2.5 py-0.5 rounded border border-white/10">
              {flows.length} flows logged in session
            </div>
          </div>

          <div className="overflow-x-auto min-h-[480px]">
            <table className="w-full text-left border-collapse text-[11px] mono">
              <thead>
                <tr className="border-b border-white/5 text-muted-foreground uppercase text-[9px] tracking-wider">
                  <th className="py-2.5">Timestamp</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Proto</th>
                  <th>Classification</th>
                  <th>Risk Index</th>
                  <th className="text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                <AnimatePresence initial={false}>
                  {flows.length > 0 ? (
                    flows.map((flow) => {
                      const isThreat = flow.classification === 'Threat';
                      return (
                        <motion.tr
                          key={flow.flow_id}
                          initial={{ opacity: 0, x: -10 }}
                          animate={{ opacity: 1, x: 0 }}
                          exit={{ opacity: 0 }}
                          transition={{ duration: 0.3 }}
                          className="border-b border-white/5 hover:bg-white/[0.01] transition-colors group cursor-pointer"
                          onClick={() => setSelectedFlow(flow)}
                        >
                          <td className="py-3 text-muted-foreground">
                            {new Date(flow.timestamp * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                          </td>
                          <td className="font-semibold">{flow.src_ip}:{flow.src_port}</td>
                          <td className="font-semibold">{flow.dst_ip}:{flow.dst_port}</td>
                          <td>
                            <span className="opacity-75">{flow.protocol}</span>
                          </td>
                          <td>
                            <Badge variant={isThreat ? 'threat' : 'benign'}>
                              {flow.classification}
                            </Badge>
                          </td>
                          <td>
                            <span className={isThreat ? 'text-threat font-bold' : 'text-benign'}>
                              {flow.risk_score}
                            </span>
                          </td>
                          <td className="text-right space-x-2">
                            <Badge variant={isThreat ? 'threat' : 'secondary'} className="uppercase text-[9px] font-bold tracking-wider mr-2">
                              {isThreat ? 'BLOCK' : 'ALLOW'}
                            </Badge>
                            <Button 
                              size="sm" 
                              variant="ghost" 
                              className="h-7 px-2.5 text-[9px] uppercase mono border border-white/5 hover:bg-white/5 hover:text-primary"
                              onClick={(e) => {
                                e.stopPropagation();
                                setSelectedFlow(flow);
                              }}
                            >
                              Inspect
                            </Button>
                          </td>
                        </motion.tr>
                      );
                    })
                  ) : (
                    <tr>
                      <td colSpan={7} className="text-center py-20 text-[10px] text-muted-foreground uppercase tracking-widest leading-loose">
                        <Activity className="w-8 h-8 text-muted-foreground/30 mx-auto mb-3 animate-pulse" />
                        {isCapturing ? 'Sniffing interface packets... Awaiting flow timeouts.' : 'Capture engine idle. Start interface capture above.'}
                      </td>
                    </tr>
                  )}
                </AnimatePresence>
              </tbody>
            </table>
          </div>
        </Card>

        {/* Drilldown details Panel */}
        <Card className="lg:col-span-4 p-6 border border-white/5 bg-gradient-to-br from-card/20 to-transparent flex flex-col justify-between">
          {selectedFlow ? (
            <div className="space-y-6">
              <div>
                <Badge variant={selectedFlow.classification === 'Threat' ? 'threat' : 'benign'} className="mb-2">
                  {selectedFlow.severity} ALERT
                </Badge>
                <h3 className="text-sm font-black text-white mono truncate">{selectedFlow.flow_id}</h3>
                <p className="text-[9px] text-muted-foreground uppercase mono mt-1">Flow Details and Feature Profiling</p>
              </div>

              <Separator className="bg-white/5" />

              <div className="space-y-3 text-[10px] mono">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Source Socket:</span>
                  <span className="font-bold">{selectedFlow.src_ip}:{selectedFlow.src_port}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Destination Socket:</span>
                  <span className="font-bold">{selectedFlow.dst_ip}:{selectedFlow.dst_port}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Target SNI Host:</span>
                  <span className="font-bold text-primary truncate max-w-[160px]">{selectedFlow.sni || 'N/A'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">TLS Version:</span>
                  <span className="font-bold">{selectedFlow.tls_version || 'N/A'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">JA3 Hash:</span>
                  <span className="font-bold truncate max-w-[160px]">{selectedFlow.ja3_hash || 'N/A'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Flow Duration:</span>
                  <span className="font-bold">{selectedFlow.flow_duration?.toFixed(2)}s</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Total Bytes:</span>
                  <span className="font-bold">{selectedFlow.bytes_sent + selectedFlow.bytes_received} B</span>
                </div>
              </div>

              <Separator className="bg-white/5" />

              {/* Scored components breakdown */}
              <div className="space-y-3">
                <div className="text-[10px] uppercase font-bold text-muted-foreground tracking-wider">Risk Matrix</div>
                <div className="space-y-2">
                  <div className="flex justify-between text-[9px] mono">
                    <span>ML Confidence Score:</span>
                    <span className="font-bold text-slate-200">{selectedFlow.ml_confidence_score || 0}%</span>
                  </div>
                  <div className="flex justify-between text-[9px] mono">
                    <span>Threat Intelligence Match:</span>
                    <span className="font-bold text-slate-200">{selectedFlow.threat_intel_score || 0}%</span>
                  </div>
                  <div className="flex justify-between text-[9px] mono">
                    <span>TLS Anomaly score:</span>
                    <span className="font-bold text-slate-200">{selectedFlow.tls_risk_score || 0}%</span>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="h-full flex flex-col items-center justify-center text-center text-muted-foreground py-20">
              <Eye className="w-10 h-10 text-muted-foreground/20 mb-3" />
              <p className="text-[10px] uppercase mono tracking-widest leading-loose">Select a flow from the live feed to inspect its metrics</p>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
