import React from 'react';
import { motion } from 'framer-motion';
import { 
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
  LineChart, Line
} from 'recharts';
import { Cpu, Award, Target, TrendingUp, Info } from 'lucide-react';
import { Card } from './ui/card';
import { Separator } from './ui/separator';

export default function Analytics() {
  
  // XGBoost Top Feature Importances (from train.py & SHAP values)
  const featureImportances = [
    { name: 'SYN Flag Count', value: 0.245 },
    { name: 'Flow Bytes/s', value: 0.182 },
    { name: 'Flow IAT Std', value: 0.145 },
    { name: 'Fwd Packet Length Std', value: 0.112 },
    { name: 'Total Backward Packets', value: 0.089 },
    { name: 'Flow Duration', value: 0.076 },
    { name: 'Down/Up Ratio', value: 0.054 },
    { name: 'Fwd PSH Flags', value: 0.042 },
    { name: 'Fwd IAT Mean', value: 0.035 },
    { name: 'Bwd Packet Length Max', value: 0.020 }
  ];

  // ROC Curve Data points
  const rocCurveData = [
    { fpr: 0, tpr: 0 },
    { fpr: 0.01, tpr: 0.85 },
    { fpr: 0.02, tpr: 0.95 },
    { fpr: 0.03, tpr: 0.98 },
    { fpr: 0.05, tpr: 0.99 },
    { fpr: 0.1, tpr: 0.999 },
    { fpr: 0.5, tpr: 1.0 },
    { fpr: 1.0, tpr: 1.0 }
  ];

  const containerVariants = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: { staggerChildren: 0.1 }
    }
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 10 },
    show: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 100 } }
  };

  return (
    <motion.div 
      variants={containerVariants}
      initial="hidden"
      animate="show"
      className="space-y-6"
    >
      {/* Page Header */}
      <div className="flex justify-between items-end border-b border-white/5 pb-6">
        <div>
          <h2 className="text-2xl font-black tracking-tight text-white uppercase italic">Model Diagnostics</h2>
          <p className="text-[10px] text-muted-foreground uppercase mono tracking-[0.15em] mt-1">
            XGBoost training evaluations and feature contribution importances
          </p>
        </div>
      </div>

      {/* Metric Cards Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <motion.div variants={itemVariants}>
          <Card className="p-4 border border-white/5 bg-black/40 text-center space-y-1">
            <div className="text-[9px] uppercase font-bold text-muted-foreground tracking-widest flex items-center justify-center gap-1.5">
              <Target className="w-3.5 h-3.5 text-primary" /> F1 Score
            </div>
            <div className="text-2xl font-black text-white">0.998</div>
          </Card>
        </motion.div>

        <motion.div variants={itemVariants}>
          <Card className="p-4 border border-white/5 bg-black/40 text-center space-y-1">
            <div className="text-[9px] uppercase font-bold text-muted-foreground tracking-widest flex items-center justify-center gap-1.5">
              <Award className="w-3.5 h-3.5 text-primary" /> Precision
            </div>
            <div className="text-2xl font-black text-white">0.999</div>
          </Card>
        </motion.div>

        <motion.div variants={itemVariants}>
          <Card className="p-4 border border-white/5 bg-black/40 text-center space-y-1">
            <div className="text-[9px] uppercase font-bold text-muted-foreground tracking-widest flex items-center justify-center gap-1.5">
              <TrendingUp className="w-3.5 h-3.5 text-primary" /> Recall
            </div>
            <div className="text-2xl font-black text-white">0.997</div>
          </Card>
        </motion.div>

        <motion.div variants={itemVariants}>
          <Card className="p-4 border border-white/5 bg-black/40 text-center space-y-1">
            <div className="text-[9px] uppercase font-bold text-muted-foreground tracking-widest flex items-center justify-center gap-1.5">
              <Cpu className="w-3.5 h-3.5 text-primary" /> ROC-AUC
            </div>
            <div className="text-2xl font-black text-white">0.9998</div>
          </Card>
        </motion.div>
      </div>

      {/* Grid: Feature Importance (left) / Confusion Matrix & ROC (right) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Feature Importance */}
        <motion.div variants={itemVariants} className="lg:col-span-6">
          <Card className="p-6 border border-white/5 bg-black/40 space-y-4">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">Feature Importance Ranking</h3>
              <p className="text-[10px] text-muted-foreground">Information gain contribution in XGBoost decision trees</p>
            </div>
            <div className="h-96 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={featureImportances} layout="vertical" margin={{ top: 10, right: 10, left: 35, bottom: 5 }}>
                  <XAxis type="number" stroke="#555" fontSize={8} />
                  <YAxis dataKey="name" type="category" stroke="#888" fontSize={8} tickLine={false} />
                  <Tooltip contentStyle={{ backgroundColor: '#0B0B0C', border: '1px solid #1E1E22', fontSize: '9px' }} />
                  <Bar dataKey="value" radius={[0, 3, 3, 0]} barSize={12}>
                    {featureImportances.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={index === 0 ? '#00F2FF' : '#3498DB'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </Card>
        </motion.div>

        {/* Right: Confusion Matrix & ROC Curve */}
        <motion.div variants={itemVariants} className="lg:col-span-6 space-y-6">
          {/* Confusion Matrix */}
          <Card className="p-6 border border-white/5 bg-black/40 space-y-4">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">Confusion Matrix</h3>
              <p className="text-[10px] text-muted-foreground">Verification predictions vs actual dataset labels</p>
            </div>
            
            <div className="grid grid-cols-3 gap-2 text-center text-[10px] mono">
              {/* Head labels */}
              <div />
              <div className="text-muted-foreground uppercase font-bold py-1 bg-white/[0.01] border border-white/5 rounded">Pred Benign</div>
              <div className="text-muted-foreground uppercase font-bold py-1 bg-white/[0.01] border border-white/5 rounded">Pred Threat</div>

              {/* Row 1 */}
              <div className="text-muted-foreground uppercase font-bold flex items-center justify-center bg-white/[0.01] border border-white/5 rounded">Actual Benign</div>
              <div className="p-4 border border-white/5 bg-benign/[0.03] rounded-lg">
                <div className="text-base font-black text-benign">98.5%</div>
                <span className="text-[8px] text-muted-foreground uppercase tracking-tight">True Neg (TN)</span>
              </div>
              <div className="p-4 border border-white/5 bg-threat/[0.01] rounded-lg">
                <div className="text-base font-black text-muted-foreground">1.5%</div>
                <span className="text-[8px] text-muted-foreground uppercase tracking-tight">False Pos (FP)</span>
              </div>

              {/* Row 2 */}
              <div className="text-muted-foreground uppercase font-bold flex items-center justify-center bg-white/[0.01] border border-white/5 rounded">Actual Threat</div>
              <div className="p-4 border border-white/5 bg-threat/[0.01] rounded-lg">
                <div className="text-base font-black text-muted-foreground">0.3%</div>
                <span className="text-[8px] text-muted-foreground uppercase tracking-tight">False Neg (FN)</span>
              </div>
              <div className="p-4 border border-white/5 bg-threat/[0.03] rounded-lg">
                <div className="text-base font-black text-threat">99.7%</div>
                <span className="text-[8px] text-muted-foreground uppercase tracking-tight">True Pos (TP)</span>
              </div>
            </div>
          </Card>

          {/* ROC-AUC Chart */}
          <Card className="p-6 border border-white/5 bg-black/40 space-y-4">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">Receiver Operating Characteristic (ROC)</h3>
              <p className="text-[10px] text-muted-foreground">False Positive Rate vs True Positive Rate</p>
            </div>
            <div className="h-44 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={rocCurveData} margin={{ top: 5, right: 10, left: -25, bottom: 5 }}>
                  <XAxis dataKey="fpr" stroke="#555" fontSize={8} label={{ value: 'FPR', position: 'insideBottomRight', offset: -5, fill: '#888', fontSize: '9px' }} />
                  <YAxis dataKey="tpr" stroke="#555" fontSize={8} label={{ value: 'TPR', position: 'insideLeft', offset: 10, fill: '#888', fontSize: '9px' }} />
                  <Tooltip contentStyle={{ backgroundColor: '#0B0B0C', border: '1px solid #1E1E22', fontSize: '9px' }} />
                  <Line type="monotone" dataKey="tpr" stroke="#00F2FF" strokeWidth={1.5} dot={false} />
                  {/* Diagonal line */}
                  <Line type="linear" dataKey="fpr" stroke="#333" strokeDasharray="3 3" dot={false} activeDot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </Card>
        </motion.div>
      </div>

      {/* Model Commentary */}
      <motion.div variants={itemVariants}>
        <Card className="p-4 border border-white/5 bg-black/40 text-[10px] mono text-muted-foreground leading-relaxed flex items-start gap-2">
          <Info className="w-4 h-4 text-primary shrink-0 mt-0.5" />
          <div>
            <span className="font-bold text-slate-200 uppercase tracking-wide">Research Diagnostics Commentary</span>
            <p className="opacity-90 mt-0.5">
              The tree-boosting classifier shows high resilience to TLS cipher variation. `SYN Flag Count` is the largest binary discriminator, indicating high predictive sensitivity for port scans and syn-flood payloads. The low FP rate (1.5%) prevents alert fatigue for SOC analysts.
            </p>
          </div>
        </Card>
      </motion.div>
    </motion.div>
  );
}
