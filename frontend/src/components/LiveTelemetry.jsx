import React, { useEffect, useState, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Play, Square, Wifi, WifiOff, Cpu, Layers, AlertCircle, Eye, 
  ChevronRight, RefreshCw, Activity, Terminal, ShieldAlert, ShieldCheck, X
} from 'lucide-react';
import { Card } from './ui/card';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import { Separator } from './ui/separator';

export default function LiveTelemetry({ socketUrl, sessionFlows = [], setSessionFlows = () => {} }) {
  const [interfaces, setInterfaces] = useState([]);
  const [selectedInterface, setSelectedInterface] = useState('');
  const [isCapturing, setIsCapturing] = useState(false);
  const [isConnected, setIsConnected] = useState(false);
  const [selectedFlow, setSelectedFlow] = useState(null);
  const [loading, setLoading] = useState(false);
  const [allowLoading, setAllowLoading] = useState(false);

  const flows = sessionFlows;
  const setFlows = setSessionFlows;

  const socketRef = useRef(null);

  // 1. Fetch available interfaces and current capture status
  const fetchInterfacesAndStatus = async () => {
    setLoading(true);
    try {
      const ifaceResponse = await fetch(`${socketUrl}/api/interfaces`);
      let ifaceList = [];
      if (ifaceResponse.ok) {
        ifaceList = await ifaceResponse.json();
        setInterfaces(ifaceList);
      }

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
          setFlows(prev => {
            if (prev.some(f => f.flow_id === msg.data.flow_id)) return prev;
            return [msg.data, ...prev].slice(0, 500);
          });
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
    setLoading(true);
    try {
      const response = await fetch(`${socketUrl}/api/capture/start?interface_name=${selectedInterface}`, {
        method: 'POST'
      });
      if (response.ok) {
        setIsCapturing(true);
        setFlows([]); // Clear previous session flows
        setSelectedFlow(null);
      }
    } catch (err) {
      console.error("Failed to initialize capture:", err);
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
      console.error("Failed to stop capture:", err);
    } finally {
      setLoading(false);
    }
  };

  const handleAllowFlow = async (e, flowId) => {
    if (e) e.stopPropagation();
    setAllowLoading(true);
    try {
      const response = await fetch(`${socketUrl}/api/flows/${flowId}/allow`, {
        method: 'POST'
      });
      if (response.ok) {
        setSelectedFlow(null);
        // Refresh local lists
        setFlows(prev => prev.map(f => {
          if (f.flow_id === flowId) {
            return { ...f, classification: 'Benign', severity: 'Safe', risk_score: 0 };
          }
          return f;
        }));
      }
    } catch (err) {
      console.error("Failed to whitelist flow:", err);
    } finally {
      setAllowLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-4 border-b border-slate-200 pb-6">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-slate-900">Real-Time Traffic Stream</h2>
          <p className="text-xs text-slate-500 mt-1">
            Perform live wiretapping on selected NIC interface to verify classification throughput
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs font-semibold text-emerald-600 bg-emerald-50 px-3.5 py-1.5 rounded-lg border border-emerald-200">
          <Activity className="w-3.5 h-3.5 animate-pulse" /> Live Analysis Active
        </div>
      </div>

      {/* Control panel: Select interface and run capture */}
      <div className="flex flex-col md:flex-row justify-between items-center gap-4 bg-white border border-slate-200 p-4 rounded-xl shadow-sm">
        <div className="flex items-center gap-3 w-full md:w-auto">
          <Layers className="w-4 h-4 text-slate-500" />
          <span className="text-xs font-medium text-slate-700">Network Interface card (NIC):</span>
          <select 
            value={selectedInterface} 
            onChange={(e) => setSelectedInterface(e.target.value)}
            disabled={isCapturing || loading}
            className="text-xs bg-slate-50 border border-slate-200 rounded px-2.5 py-1 text-slate-800 focus:outline-none"
          >
            {interfaces.map(iface => (
              <option key={iface.name} value={iface.pcap_name || iface.name}>
                {iface.name} [{iface.ip || 'no-ip'}]
              </option>
            ))}
          </select>
        </div>

        <div className="flex items-center gap-4 w-full md:w-auto justify-end">
          <div className="flex items-center gap-2">
            <span className="relative flex h-2.5 w-2.5">
              {isCapturing ? (
                <>
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
                </>
              ) : (
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-slate-300"></span>
              )}
            </span>
            <span className="text-[10px] uppercase font-bold mono text-slate-500">
              {isCapturing ? 'Ingestion Engine Running' : 'Ingestion Engine Stopped'}
            </span>
          </div>

          {isCapturing ? (
            <Button
              size="sm"
              onClick={handleStopCapture}
              disabled={loading}
              className="bg-red-600 hover:bg-red-700 text-white font-medium text-xs px-4"
            >
              <Square className="w-3.5 h-3.5 mr-2 fill-current" /> Terminate Capture
            </Button>
          ) : (
            <Button
              size="sm"
              onClick={handleStartCapture}
              disabled={loading || !selectedInterface}
              className="bg-slate-900 hover:bg-slate-800 text-white font-medium text-xs px-4"
            >
              <Play className="w-3.5 h-3.5 mr-2 fill-current" /> Initialize Capture
            </Button>
          )}
        </div>
      </div>

      {/* Main split display: 8 cols table / 4 cols drilldown */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        <Card className="lg:col-span-8 p-6 border border-slate-200 bg-white flex flex-col justify-between shadow-sm">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700">Live Traffic Feed</h3>
              <p className="text-[10px] text-slate-500 mt-0.5">Rolling list of recent analyzed bidirectional flows</p>
            </div>
            <div className="text-[9px] mono text-slate-500 uppercase bg-slate-50 px-2.5 py-0.5 rounded border border-slate-200">
              {flows.length} flows logged
            </div>
          </div>

          <div className="overflow-x-auto min-h-[480px]">
            <table className="w-full text-left border-collapse text-xs mono">
              <thead>
                <tr className="border-b border-slate-200 text-slate-500 uppercase text-[9px] tracking-wider font-semibold">
                  <th className="py-2.5 px-2">Timestamp</th>
                  <th className="px-2">Source</th>
                  <th className="px-2">Destination</th>
                  <th className="px-2">Proto</th>
                  <th className="px-2">Classification</th>
                  <th className="px-2">Risk</th>
                  <th className="text-right px-2">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                <AnimatePresence initial={false}>
                  {flows.length > 0 ? (
                    flows.map((flow) => {
                      const isThreat = (flow.classification || 'Benign') === 'Threat';
                      return (
                        <motion.tr
                          key={flow.flow_id}
                          initial={{ opacity: 0, x: -10 }}
                          animate={{ opacity: 1, x: 0 }}
                          exit={{ opacity: 0 }}
                          transition={{ duration: 0.2 }}
                          className={`hover:bg-slate-50/50 cursor-pointer ${selectedFlow?.flow_id === flow.flow_id ? 'bg-slate-50' : ''}`}
                          onClick={() => setSelectedFlow(flow)}
                        >
                          <td className="py-3 px-2 text-slate-400">
                            {new Date(flow.timestamp * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                          </td>
                          <td className="font-semibold px-2 text-slate-800">{flow.src_ip}:{flow.src_port}</td>
                          <td className="font-semibold px-2 text-slate-800">{flow.dst_ip}:{flow.dst_port}</td>
                          <td className="px-2 text-slate-500">{flow.protocol}</td>
                          <td className="px-2">
                            <Badge variant={isThreat ? 'threat' : 'benign'}>
                              {flow.classification || 'Benign'}
                            </Badge>
                          </td>
                          <td className="px-2">
                            <span className={isThreat ? 'text-red-600 font-bold' : 'text-emerald-600 font-medium'}>
                              {flow.risk_score || 0}
                            </span>
                          </td>
                          <td className="text-right px-2 space-x-2" onClick={e => e.stopPropagation()}>
                            <Button 
                              size="sm" 
                              variant="outline" 
                              className="h-7 px-2 text-[9px] uppercase border-slate-200 bg-white hover:bg-slate-50 text-slate-700"
                              onClick={() => setSelectedFlow(flow)}
                            >
                              Inspect
                            </Button>
                            {isThreat && (
                              <Button 
                                size="sm" 
                                className="h-7 px-2 text-[9px] bg-emerald-600 hover:bg-emerald-700 text-white font-medium"
                                onClick={(e) => handleAllowFlow(e, flow.flow_id)}
                                disabled={allowLoading}
                              >
                                Allow
                              </Button>
                            )}
                          </td>
                        </motion.tr>
                      );
                    })
                  ) : (
                    <tr>
                      <td colSpan={7} className="text-center py-20 text-xs text-slate-400 uppercase tracking-wider font-medium">
                        {isCapturing ? 'Listening on interface for packet connection streams...' : 'Click "Initialize Capture" to start listening'}
                      </td>
                    </tr>
                  )}
                </AnimatePresence>
              </tbody>
            </table>
          </div>
        </Card>

        {/* Drill down inspector side panel: 4 cols */}
        <Card className="lg:col-span-4 p-6 border border-slate-200 bg-white min-h-[500px] shadow-sm">
          {selectedFlow ? (
            <div className="space-y-6 animate-fade-in">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Wifi className="w-4 h-4 text-slate-700" />
                  <span className="text-[9px] mono uppercase font-bold text-slate-500 tracking-widest">Flow Inspector</span>
                </div>
                <Button size="icon" variant="ghost" onClick={() => setSelectedFlow(null)} className="h-7 w-7 text-slate-400 hover:text-slate-800">
                  <X className="w-4.5 h-4.5" />
                </Button>
              </div>

              <div>
                <Badge variant={(selectedFlow.classification || 'Benign').toLowerCase() === 'threat' ? 'threat' : 'benign'} className="mb-2">
                  {selectedFlow.severity || 'Benign'} Flow
                </Badge>
                <h3 className="text-xs font-bold text-slate-900 mono truncate">{selectedFlow.flow_id}</h3>
              </div>

              <Separator className="bg-slate-200" />

              <div className="space-y-3 text-[10px] mono">
                <div className="flex justify-between">
                  <span className="text-slate-400">Source IP:</span>
                  <span className="text-slate-800 font-semibold">{selectedFlow.src_ip}:{selectedFlow.src_port}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Destination IP:</span>
                  <span className="text-slate-800 font-semibold">{selectedFlow.dst_ip}:{selectedFlow.dst_port}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">SNI Host:</span>
                  <span className="text-indigo-600 font-semibold truncate max-w-[160px]">{selectedFlow.sni || '-'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Protocol Details:</span>
                  <span className="text-slate-800 font-bold">
                    {selectedFlow.protocol === 17 || selectedFlow.protocol === 'UDP' ? 'UDP' : (
                      [
                        selectedFlow.syn_count > 0 && 'SYN',
                        selectedFlow.ack_count > 0 && 'ACK',
                        selectedFlow.rst_count > 0 && 'RST',
                        selectedFlow.fin_count > 0 && 'FIN',
                        selectedFlow.psh_count > 0 && 'PSH'
                      ].filter(Boolean).join(' | ') || 'TCP'
                    )}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Duration:</span>
                  <span className="text-slate-800">{selectedFlow.flow_duration?.toFixed(3) || selectedFlow.duration?.toFixed(3) || '0.000'}s</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Total Bytes:</span>
                  <span className="text-slate-800">{(selectedFlow.bytes_sent || 0) + (selectedFlow.bytes_received || 0)} B</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Packets:</span>
                  <span className="text-slate-800">{selectedFlow.total_packets || 0}</span>
                </div>
              </div>

              {(selectedFlow.classification || 'Benign') === 'Threat' ? (
                <>
                  <Separator className="bg-slate-200" />
                  <div className="p-3 border border-red-200 bg-red-50/40 rounded-lg text-[10px] mono text-red-700 leading-tight space-y-1.5 animate-pulse">
                    <div className="flex items-center gap-1.5 font-bold uppercase tracking-wider">
                      <AlertCircle className="w-3.5 h-3.5 text-red-600" /> Threat Indicators Detected
                    </div>
                    <p className="opacity-90">Model Confidence: <b>{selectedFlow.confidence}%</b></p>
                    <p className="opacity-90">Reputation Score: <b>{Math.max(selectedFlow.ip_reputation_score || 0, selectedFlow.domain_reputation_score || 0)}%</b></p>
                  </div>
                  <Button 
                    onClick={(e) => handleAllowFlow(e, selectedFlow.flow_id)}
                    disabled={allowLoading}
                    className="w-full bg-emerald-600 hover:bg-emerald-700 text-white font-medium text-xs gap-1.5"
                  >
                    <ShieldCheck className="w-4 h-4" /> Allow & Whitelist Connection
                  </Button>
                </>
              ) : (
                <>
                  <Separator className="bg-slate-200" />
                  <div className="p-3 border border-emerald-200 bg-emerald-50/40 rounded-lg text-[10px] mono text-emerald-700 leading-tight flex items-center gap-1.5">
                    <ShieldCheck className="w-4 h-4" /> Allowed Connection (Safe)
                  </div>
                </>
              )}
            </div>
          ) : (
            <div className="h-full flex flex-col items-center justify-center text-center text-slate-400 py-20">
              <Eye className="w-8 h-8 text-slate-300 mb-3" />
              <p className="text-xs font-medium tracking-normal leading-loose">Select a flow to inspect real-time packet properties</p>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
