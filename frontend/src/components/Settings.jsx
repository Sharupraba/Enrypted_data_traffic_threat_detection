import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Settings as SettingsIcon, Shield, Sliders, Key, Clock, 
  Save, RefreshCw, CheckCircle, AlertTriangle, Loader2
} from 'lucide-react';
import { Card } from './ui/card';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Separator } from './ui/separator';

export default function Settings({ apiEndpoint }) {
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState('');

  // Settings State
  const [abuseipdbKey, setAbuseipdbKey] = useState('');
  const [virustotalKey, setVirusTotalKey] = useState('');
  const [xgboostThreshold, setXgboostThreshold] = useState(50);
  const [anomalyThreshold, setAnomalyThreshold] = useState(50);
  const [idleTimeout, setIdleTimeout] = useState(8);
  const [activeTimeout, setActiveTimeout] = useState(120);

  const fetchSettings = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`${apiEndpoint}/api/settings`);
      if (res.ok) {
        const data = await res.json();
        setAbuseipdbKey(data.abuseipdb_key || '');
        setVirusTotalKey(data.virustotal_key || '');
        setXgboostThreshold(data.xgboost_threshold || 50);
        setAnomalyThreshold(data.anomaly_threshold || 50);
        setIdleTimeout(data.idle_timeout || 8);
        setActiveTimeout(data.active_timeout || 120);
      } else {
        throw new Error('Failed to load settings from server.');
      }
    } catch (err) {
      console.error(err);
      setError('Cannot load system settings. Please verify the backend is online.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSettings();
  }, [apiEndpoint]);

  const handleSave = async (e) => {
    e.preventDefault();
    setSaving(true);
    setSuccess(false);
    setError('');

    const payload = {
      abuseipdb_key: abuseipdbKey,
      virustotal_key: virustotalKey,
      xgboost_threshold: parseFloat(xgboostThreshold),
      anomaly_threshold: parseFloat(anomalyThreshold),
      idle_timeout: parseFloat(idleTimeout),
      active_timeout: parseFloat(activeTimeout)
    };

    try {
      const res = await fetch(`${apiEndpoint}/api/settings`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (res.ok) {
        setSuccess(true);
        setTimeout(() => setSuccess(false), 4000);
      } else {
        const data = await res.json();
        throw new Error(data.detail || 'Save failed.');
      }
    } catch (err) {
      console.error(err);
      setError('Failed to update system settings: ' + err.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-4 border-b border-slate-200 pb-6">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-slate-900 flex items-center gap-2">
            <SettingsIcon className="w-5 h-5 text-slate-700" /> System Configurations
          </h2>
          <p className="text-xs text-slate-500 mt-1">
            Manage threat reputation API keys, ML classification thresholds, and flow timeouts
          </p>
        </div>
        <Button onClick={fetchSettings} disabled={loading} variant="outline" className="border-slate-200 bg-white hover:bg-slate-50 text-xs font-medium">
          <RefreshCw className={`w-3.5 h-3.5 mr-2 ${loading ? 'animate-spin' : ''}`} /> Refresh
        </Button>
      </div>

      {loading ? (
        <div className="py-32 flex flex-col items-center justify-center space-y-3">
          <Loader2 className="w-8 h-8 text-slate-800 animate-spin" />
          <span className="text-xs text-slate-400">Syncing System settings...</span>
        </div>
      ) : (
        <form onSubmit={handleSave} className="max-w-4xl mx-auto space-y-6">
          {/* Status Banners */}
          {success && (
            <div className="p-4 border border-emerald-200 bg-emerald-50 text-xs text-emerald-700 font-semibold rounded-xl flex items-center gap-3 mono animate-fade-in shadow-xs">
              <CheckCircle className="w-4 h-4 text-emerald-600 shrink-0" />
              <span>SYSTEM SETTINGS APPLIED AND PERSISTED SUCCESSFULLY!</span>
            </div>
          )}
          {error && (
            <div className="p-4 border border-red-200 bg-red-50 text-xs text-red-700 font-semibold rounded-xl flex items-center gap-3 mono animate-fade-in shadow-xs">
              <AlertTriangle className="w-4 h-4 text-red-500 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Column 1: API Integrations */}
            <Card className="p-6 border border-slate-200 bg-white space-y-6 relative overflow-hidden shadow-sm">
              <div className="absolute top-0 left-0 w-full h-[3px] bg-slate-900" />
              <div className="flex items-center gap-2.5 text-slate-800">
                <Key className="w-4 h-4 text-slate-500" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700">Threat Intelligence APIs</h3>
              </div>
              <p className="text-[10px] text-slate-500 leading-relaxed font-semibold">
                Configure your custom API keys for AbuseIPDB and VirusTotal. These keys are used to dynamically enrich active threat telemetry.
              </p>
              <Separator className="bg-slate-100" />
              
              <div className="space-y-4">
                <div className="space-y-1.5">
                  <label className="text-[9px] mono uppercase font-bold text-slate-600 tracking-wider">AbuseIPDB API Key (v2)</label>
                  <Input 
                    type="password" 
                    value={abuseipdbKey}
                    onChange={(e) => setAbuseipdbKey(e.target.value)}
                    placeholder="Enter AbuseIPDB Key..."
                    className="bg-slate-50 border-slate-200 focus-visible:ring-slate-300 text-xs text-slate-800"
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="text-[9px] mono uppercase font-bold text-slate-600 tracking-wider">VirusTotal API Key (v3)</label>
                  <Input 
                    type="password" 
                    value={virustotalKey}
                    onChange={(e) => setVirusTotalKey(e.target.value)}
                    placeholder="Enter VirusTotal Key..."
                    className="bg-slate-50 border-slate-200 focus-visible:ring-slate-300 text-xs text-slate-800"
                  />
                </div>
              </div>
            </Card>

            {/* Column 2: ML & Flow Timeouts */}
            <Card className="p-6 border border-slate-200 bg-white space-y-6 relative overflow-hidden shadow-sm">
              <div className="absolute top-0 left-0 w-full h-[3px] bg-slate-900" />
              <div className="flex items-center gap-2.5 text-slate-800">
                <Sliders className="w-4 h-4 text-slate-500" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700">Detection Sensitivity</h3>
              </div>
              <p className="text-[10px] text-slate-500 leading-relaxed font-semibold">
                Tweak the sensitivity of the ML pipeline. Lower thresholds increase detection capture but may produce false alerts.
              </p>
              <Separator className="bg-slate-100" />
              
              <div className="space-y-5">
                <div className="space-y-2">
                  <div className="flex justify-between text-[9px] mono font-bold text-slate-600">
                    <span>XGBoost Classifier Threshold</span>
                    <span>{xgboostThreshold}%</span>
                  </div>
                  <input 
                    type="range" 
                    min="10" 
                    max="90" 
                    value={xgboostThreshold}
                    onChange={(e) => setXgboostThreshold(e.target.value)}
                    className="w-full accent-slate-900 cursor-pointer"
                  />
                </div>
                
                <div className="space-y-2">
                  <div className="flex justify-between text-[9px] mono font-bold text-slate-600">
                    <span>Zero-Day Anomaly Threshold</span>
                    <span>{anomalyThreshold}%</span>
                  </div>
                  <input 
                    type="range" 
                    min="10" 
                    max="90" 
                    value={anomalyThreshold}
                    onChange={(e) => setAnomalyThreshold(e.target.value)}
                    className="w-full accent-slate-900 cursor-pointer"
                  />
                </div>

                <Separator className="bg-slate-100" />

                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-1.5">
                    <label className="text-[9px] mono uppercase font-bold text-slate-600 tracking-wider flex items-center gap-1">
                      <Clock className="w-3 h-3 text-slate-400" /> Idle Timeout (s)
                    </label>
                    <Input 
                      type="number" 
                      value={idleTimeout}
                      onChange={(e) => setIdleTimeout(e.target.value)}
                      className="bg-slate-50 border-slate-200 focus-visible:ring-slate-300 text-xs text-slate-800"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-[9px] mono uppercase font-bold text-slate-600 tracking-wider flex items-center gap-1">
                      <Clock className="w-3 h-3 text-slate-400" /> Active Timeout (s)
                    </label>
                    <Input 
                      type="number" 
                      value={activeTimeout}
                      onChange={(e) => setActiveTimeout(e.target.value)}
                      className="bg-slate-50 border-slate-200 focus-visible:ring-slate-300 text-xs text-slate-800"
                    />
                  </div>
                </div>
              </div>
            </Card>
          </div>

          {/* Form Actions */}
          <div className="flex justify-end gap-3 pt-2">
            <Button 
              type="button" 
              variant="outline" 
              onClick={fetchSettings}
              disabled={saving}
              className="text-xs"
            >
              Reset Changes
            </Button>
            <Button 
              type="submit" 
              disabled={saving}
              className="bg-slate-900 hover:bg-slate-800 text-white font-medium text-xs px-6 gap-2"
            >
              {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
              Save Configuration
            </Button>
          </div>
        </form>
      )}
    </div>
  );
}
