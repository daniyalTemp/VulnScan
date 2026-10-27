import React from 'react';
import {
  ShieldAlert,
  Flame,
  Lock,
  AlertTriangle,
  Layers,
  CheckCircle2,
} from 'lucide-react';
import { CrawlStats } from '../types/vulnerability';

interface MetricsHudProps {
  stats: CrawlStats;
  onFilterBySeverity: (severity: 'CRITICAL' | 'HIGH' | 'ALL') => void;
  onFilterExploited: () => void;
  onFilterRansomware: () => void;
  activeFilterDescription?: string;
}

export const MetricsHud: React.FC<MetricsHudProps> = ({
  stats,
  onFilterBySeverity,
  onFilterExploited,
  onFilterRansomware,
}) => {
  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mb-6">
      
      {/* Total Vulnerabilities */}
      <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800/80 hover:border-slate-700 transition-all">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-medium text-slate-400">کل آسیب‌پذیری‌ها</span>
          <Layers className="w-4 h-4 text-cyan-400" />
        </div>
        <div className="flex items-baseline gap-2">
          <span className="text-2xl font-bold font-mono text-white">{stats.total}</span>
          <span className="text-[11px] text-slate-400">شناسه ثبت‌شده</span>
        </div>
      </div>

      {/* Critical Severity (CVSS 9.0+) */}
      <button
        onClick={() => onFilterBySeverity('CRITICAL')}
        className="text-right p-4 rounded-xl bg-rose-950/20 border border-rose-900/40 hover:border-rose-600/70 hover:bg-rose-950/30 transition-all group"
      >
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-semibold text-rose-300">بحرانی (Critical)</span>
          <div className="w-2 h-2 rounded-full bg-rose-500 animate-ping" />
        </div>
        <div className="flex items-baseline gap-2">
          <span className="text-2xl font-bold font-mono text-rose-400 group-hover:scale-105 transition-transform">
            {stats.critical}
          </span>
          <span className="text-[11px] text-rose-300/70">CVSS ≥ 9.0</span>
        </div>
      </button>

      {/* Actively Exploited (In the Wild / CISA KEV) */}
      <button
        onClick={onFilterExploited}
        className="text-right p-4 rounded-xl bg-amber-950/20 border border-amber-900/40 hover:border-amber-600/70 hover:bg-amber-950/30 transition-all group"
      >
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-semibold text-amber-300">بهره‌برداری فعال</span>
          <Flame className="w-4 h-4 text-amber-400" />
        </div>
        <div className="flex items-baseline gap-2">
          <span className="text-2xl font-bold font-mono text-amber-400 group-hover:scale-105 transition-transform">
            {stats.activelyExploited}
          </span>
          <span className="text-[11px] text-amber-300/70">کاتالوگ CISA KEV</span>
        </div>
      </button>

      {/* Ransomware Threat Vector */}
      <button
        onClick={onFilterRansomware}
        className="text-right p-4 rounded-xl bg-purple-950/20 border border-purple-900/40 hover:border-purple-600/70 hover:bg-purple-950/30 transition-all group"
      >
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-semibold text-purple-300">حملات باج‌افزاری</span>
          <Lock className="w-4 h-4 text-purple-400" />
        </div>
        <div className="flex items-baseline gap-2">
          <span className="text-2xl font-bold font-mono text-purple-400 group-hover:scale-105 transition-transform">
            {stats.ransomwareLinked}
          </span>
          <span className="text-[11px] text-purple-300/70">استفاده در باج‌افزار</span>
        </div>
      </button>

      {/* High Severity */}
      <button
        onClick={() => onFilterBySeverity('HIGH')}
        className="text-right p-4 rounded-xl bg-orange-950/20 border border-orange-900/40 hover:border-orange-600/70 hover:bg-orange-950/30 transition-all group"
      >
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-semibold text-orange-300">سطح خطر بالا</span>
          <AlertTriangle className="w-4 h-4 text-orange-400" />
        </div>
        <div className="flex items-baseline gap-2">
          <span className="text-2xl font-bold font-mono text-orange-400 group-hover:scale-105 transition-transform">
            {stats.high}
          </span>
          <span className="text-[11px] text-orange-300/70">CVSS 7.0 - 8.9</span>
        </div>
      </button>

      {/* Resolved or Under Control */}
      <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800/80">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-medium text-emerald-300">رفع‌شده / تحت نظر</span>
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
        </div>
        <div className="flex items-baseline gap-2">
          <span className="text-2xl font-bold font-mono text-emerald-400">
            {stats.resolved + stats.watching}
          </span>
          <span className="text-[11px] text-slate-400">مورد اقدام تیم</span>
        </div>
      </div>

    </div>
  );
};
