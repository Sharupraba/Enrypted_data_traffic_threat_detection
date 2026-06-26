import React from 'react';
import { 
  Radar, 
  RadarChart, 
  PolarGrid, 
  PolarAngleAxis, 
  PolarRadiusAxis, 
  ResponsiveContainer,
  Tooltip
} from 'recharts';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { ShieldAlert } from 'lucide-react';

export default function CombatRadar({ results }) {
  // Synthesize metrics from flow data for visualization
  const data = [
    { subject: 'Volume', A: Math.min(100, results.total_flows / 10), fullMark: 100 },
    { subject: 'Severity', A: (results.threat_count / results.total_flows) * 100 || 0, fullMark: 100 },
    { subject: 'Persistence', A: 65, fullMark: 100 }, // Mock metric
    { subject: 'Diversity', A: new Set(results.results.map(r => r.dst_ip)).size * 5, fullMark: 100 },
    { subject: 'Encryption', A: 85, fullMark: 100 }, // This is an encrypted traffic tool
    { subject: 'Anomalies', A: results.threat_count * 2, fullMark: 100 },
  ];

  return (
    <Card className="bg-card/30 backdrop-blur-md border-primary/10 h-full">
      <CardHeader className="pb-0">
        <CardTitle className="text-[10px] text-muted-foreground flex items-center gap-2">
          <ShieldAlert className="w-3 h-3 text-threat" />
          Threat Vector Analysis
        </CardTitle>
      </CardHeader>
      <CardContent className="h-64 flex items-center justify-center p-0">
        <ResponsiveContainer width="100%" height="100%">
          <RadarChart cx="50%" cy="50%" outerRadius="80%" data={data}>
            <PolarGrid stroke="rgba(255,255,255,0.1)" />
            <PolarAngleAxis 
              dataKey="subject" 
              tick={{ fill: 'rgba(255,255,255,0.4)', fontSize: 10, fontFamily: 'monospace' }} 
            />
            <Tooltip 
              contentStyle={{ backgroundColor: '#000', border: '1px solid rgba(0,242,255,0.2)', borderRadius: '4px' }}
              itemStyle={{ color: '#00f2ff', fontSize: '10px' }}
            />
            <Radar
              name="Metrics"
              dataKey="A"
              stroke="hsl(var(--threat))"
              fill="hsl(var(--threat))"
              fillOpacity={0.3}
            />
          </RadarChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}
