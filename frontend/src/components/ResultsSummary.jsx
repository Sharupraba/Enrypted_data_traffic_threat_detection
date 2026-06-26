import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { 
  PieChart, 
  Pie, 
  Cell, 
  ResponsiveContainer, 
  Tooltip,
} from 'recharts';
import { Shield, ShieldAlert, Activity, BarChart3, Zap } from 'lucide-react';

export default function ResultsSummary({ results }) {
  const chartData = [
    { name: 'Threat', value: results.threat_count, color: 'hsl(var(--threat))' },
    { name: 'Benign', value: results.benign_count, color: 'hsl(var(--benign))' },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 animate-in fade-in slide-in-from-top-2 duration-700">
      <Card className="bg-black/40 border-white/5 backdrop-blur-sm relative overflow-hidden group">
        <div className="absolute top-0 right-0 p-4 opacity-5 group-hover:opacity-10 transition-opacity">
           <Activity className="w-16 h-16 text-primary" />
        </div>
        <CardHeader className="pb-2">
          <CardTitle className="text-[10px] font-black uppercase tracking-widest flex items-center gap-2">
            <Zap className="w-3 h-3 text-primary" />
            Total Flow Ingest
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-4xl font-black text-white italic">{results.total_flows}</div>
          <div className="flex items-center gap-2 mt-2">
             <div className="h-1 flex-1 bg-white/5 rounded-full overflow-hidden">
                <div className="h-full bg-primary" style={{ width: '100%' }} />
             </div>
             <span className="text-[9px] mono text-muted-foreground uppercase">Buffer: OK</span>
          </div>
        </CardContent>
      </Card>

      <Card className="bg-black/40 border-threat/20 backdrop-blur-sm relative overflow-hidden group">
        <div className="absolute top-0 right-0 p-4 opacity-5 group-hover:opacity-20 transition-opacity">
           <ShieldAlert className="w-16 h-16 text-threat" />
        </div>
        <CardHeader className="pb-2">
          <CardTitle className="text-[10px] font-black uppercase tracking-widest flex items-center gap-2">
            <ShieldAlert className="w-3 h-3 text-threat" />
            Detected Malware
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-4xl font-black text-threat italic leading-none">{results.threat_count}</div>
          <p className="text-[10px] text-muted-foreground mt-2 mono uppercase font-bold">
            Risk Ratio: <span className={results.threat_count > 0 ? "text-threat" : "text-benign"}>
              {((results.threat_count / results.total_flows) * 100).toFixed(2)}%
            </span>
          </p>
        </CardContent>
      </Card>

      <Card className="bg-black/40 border-white/5 backdrop-blur-sm row-span-1">
        <CardHeader className="pb-0">
          <CardTitle className="text-[10px] font-black uppercase tracking-widest flex items-center gap-2">
            <BarChart3 className="w-3 h-3 text-primary" />
            Distribution
          </CardTitle>
        </CardHeader>
        <CardContent className="h-32">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={chartData}
                cx="50%"
                cy="50%"
                innerRadius={35}
                outerRadius={45}
                paddingAngle={5}
                dataKey="value"
                stroke="none"
              >
                {chartData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip 
                contentStyle={{ backgroundColor: '#000', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '4px' }}
                itemStyle={{ color: '#fff', fontSize: '10px', textTransform: 'uppercase' }}
              />
            </PieChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>
    </div>
  );
}
