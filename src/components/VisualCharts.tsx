import React from 'react';
import {
  Globe,
  Server,
  Layers,
  Activity,
  HardDrive,
  Cpu,
  ShieldAlert,
  Radio,
} from 'lucide-react';
import { CrawlStats, VulnerabilitySource } from '../types/vulnerability';

interface VisualChartsProps {
  stats: CrawlStats;
  selectedVendor?: string;
  onSelectVendor: (vendor: string | undefined) => void;
  selectedSource?: VulnerabilitySource | 'ALL';
  onSelectSource: (source: VulnerabilitySource | 'ALL') => void;
}

export const VisualCharts: React.FC<VisualChartsProps> = ({
  stats,
  selectedVendor,
  onSelectVendor,
  selectedSource,
  onSelectSource,
}) => {
  const total = Math.max(1, stats.total);
  const critPct = Math.round((stats.critical / total) * 100);
  const highPct = Math.round((stats.high / total) * 100);
  const medPct = Math.round((stats.medium / total) * 100);
  const lowPct = Math.round((stats.low / total) * 100);

  // Highest vendor count for bar scale
  const maxVendorCount = Math.max(1, ...(stats.topVendors.map((v) => v.count) || [1]));

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
      
      {/* 1. Severity Distribution & Spectrum Visual */}
      <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Activity className="w-4 h-4 text-rose-500" />
              طیف شدت خطر (CVSS Severity)
            </h3>
            <span className="text-[11px] font-mono text-slate-400">
              {stats.total} آسیب‌پذیری
            </span>
          </div>

          <p className="text-xs text-slate-400 mb-4">
            نسبت آسیب‌پذیری‌ها بر اساس نمره استاندارد CVSS v3.1 و فوریت اقدام:
          </p>

          {/* Segmented spectrum bar */}
          <div className="w-full h-3 rounded-full overflow-hidden flex bg-slate-800 p-0.5 gap-0.5 mb-4">
            {stats.critical > 0 && (
              <div
                style={{ width: `${critPct}%` }}
                className="bg-rose-500 h-full rounded-sm transition-all duration-500"
                title={`بحرانی: ${stats.critical} (${critPct}%)`}
              />
            )}
            {stats.high > 0 && (
              <div
                style={{ width: `${highPct}%` }}
                className="bg-orange-500 h-full rounded-sm transition-all duration-500"
                title={`بالا: ${stats.high} (${highPct}%)`}
              />
            )}
            {stats.medium > 0 && (
              <div
                style={{ width: `${medPct}%` }}
                className="bg-amber-400 h-full rounded-sm transition-all duration-500"
                title={`متوسط: ${stats.medium} (${medPct}%)`}
              />
            )}
            {stats.low > 0 && (
              <div
                style={{ width: `${lowPct}%` }}
                className="bg-blue-400 h-full rounded-sm transition-all duration-500"
                title={`پایین: ${stats.low} (${lowPct}%)`}
              />
            )}
          </div>

          {/* Severity Badges Grid */}
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="p-2 rounded-lg bg-rose-500/10 border border-rose-500/20 flex items-center justify-between">
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-rose-500" />
                <span className="text-rose-200 font-medium">بحرانی (Critical)</span>
              </div>
              <span className="font-mono font-bold text-rose-300">
                {stats.critical} <span className="text-[10px] text-rose-400/70">({critPct}%)</span>
              </span>
            </div>

            <div className="p-2 rounded-lg bg-orange-500/10 border border-orange-500/20 flex items-center justify-between">
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-orange-500" />
                <span className="text-orange-200 font-medium">بالا (High)</span>
              </div>
              <span className="font-mono font-bold text-orange-300">
                {stats.high} <span className="text-[10px] text-orange-400/70">({highPct}%)</span>
              </span>
            </div>

            <div className="p-2 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-between">
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-amber-400" />
                <span className="text-amber-200 font-medium">متوسط (Medium)</span>
              </div>
              <span className="font-mono font-bold text-amber-300">
                {stats.medium} <span className="text-[10px] text-amber-400/70">({medPct}%)</span>
              </span>
            </div>

            <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-between">
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-blue-400" />
                <span className="text-blue-200 font-medium">پایین (Low)</span>
              </div>
              <span className="font-mono font-bold text-blue-300">
                {stats.low} <span className="text-[10px] text-blue-400/70">({lowPct}%)</span>
              </span>
            </div>
          </div>
        </div>

        {/* Real-world Threat Alert Pill */}
        <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <span className="flex items-center gap-1.5 text-amber-400">
            <Radio className="w-3.5 h-3.5 animate-pulse" />
            بهره‌برداری فعال تأییدشده:
          </span>
          <span className="font-mono font-bold text-amber-300">
            {stats.activelyExploited} مورد در کاتالوگ CISA
          </span>
        </div>
      </div>

      {/* 2. Top Affected Vendors (Interactive Bar Chart) */}
      <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <Server className="w-4 h-4 text-cyan-400" />
            فناوری‌ها و شرکت‌های هدف
          </h3>
          {selectedVendor && (
            <button
              onClick={() => onSelectVendor(undefined)}
              className="text-[11px] text-cyan-400 hover:underline"
            >
              پاک‌سازی فیلتر
            </button>
          )}
        </div>

        <p className="text-xs text-slate-400 mb-3">
          بیشترین رکوردهای ثبت‌شده بر اساس شرکت سازنده (برای فیلتر کلیک کنید):
        </p>

        <div className="space-y-2.5">
          {stats.topVendors.map((item) => {
            const widthPct = Math.round((item.count / maxVendorCount) * 100);
            const isSelected = selectedVendor === item.vendor;

            return (
              <button
                key={item.vendor}
                onClick={() => onSelectVendor(isSelected ? undefined : item.vendor)}
                className={`w-full text-right p-2 rounded-lg transition-all group ${
                  isSelected
                    ? 'bg-cyan-950/40 border border-cyan-500/40'
                    : 'hover:bg-slate-800/60'
                }`}
              >
                <div className="flex justify-between items-center text-xs mb-1">
                  <span className={`font-medium ${isSelected ? 'text-cyan-300 font-bold' : 'text-slate-300'}`}>
                    {item.vendor}
                  </span>
                  <span className="font-mono text-slate-400 group-hover:text-cyan-400 transition-colors">
                    {item.count} آسیب‌پذیری
                  </span>
                </div>
                <div className="w-full h-1.5 rounded-full bg-slate-800 overflow-hidden">
                  <div
                    style={{ width: `${widthPct}%` }}
                    className={`h-full rounded-full transition-all duration-500 ${
                      isSelected
                        ? 'bg-cyan-400 shadow-sm shadow-cyan-400'
                        : 'bg-gradient-to-r from-cyan-600 to-indigo-500 group-hover:from-cyan-400 group-hover:to-indigo-400'
                    }`}
                  />
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* 3. Attack Vectors & Source Intelligence */}
      <div className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Globe className="w-4 h-4 text-emerald-400" />
              بردارهای نفوذ و مراجع رسمی
            </h3>
            <span className="text-[11px] text-slate-400">تحلیل معماری حمله</span>
          </div>

          <p className="text-xs text-slate-400 mb-3">
            روش‌های دستیابی مهاجمین به سیستم‌های هدف:
          </p>

          {/* Attack Vector Cards */}
          <div className="grid grid-cols-2 gap-2 mb-4">
            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
              <div className="flex items-center gap-2 text-rose-400 text-xs font-semibold mb-1">
                <Globe className="w-3.5 h-3.5" />
                شبکه (Network / Remote)
              </div>
              <p className="text-[11px] text-slate-400">
                نفوذ از راه دور بدون دسترسی فیزیکی به شبکه داخلی
              </p>
            </div>

            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
              <div className="flex items-center gap-2 text-amber-400 text-xs font-semibold mb-1">
                <Cpu className="w-3.5 h-3.5" />
                محلی (Local / LPE)
              </div>
              <p className="text-[11px] text-slate-400">
                ارتقای دسترسی کاربر عادی به ادمین یا Root سیستم
              </p>
            </div>
          </div>

          {/* Sources Filter Pills */}
          <div className="space-y-1.5">
            <span className="text-[11px] font-semibold text-slate-400 block mb-1">
              تفکیک بر اساس مرجع کراول‌شده:
            </span>
            <div className="flex flex-wrap gap-1.5">
              <button
                onClick={() => onSelectSource('ALL')}
                className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-all ${
                  selectedSource === 'ALL'
                    ? 'bg-rose-500 text-white'
                    : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                }`}
              >
                تمام مراجع ({stats.total})
              </button>
              <button
                onClick={() => onSelectSource('CISA_KEV')}
                className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-all ${
                  selectedSource === 'CISA_KEV'
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/50'
                    : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                }`}
              >
                CISA KEV ({stats.sourcesBreakdown.CISA_KEV || 0})
              </button>
              <button
                onClick={() => onSelectSource('GITHUB_ADVISORY')}
                className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-all ${
                  selectedSource === 'GITHUB_ADVISORY'
                    ? 'bg-purple-500/20 text-purple-300 border border-purple-500/50'
                    : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                }`}
              >
                گیت‌هاب ({stats.sourcesBreakdown.GITHUB_ADVISORY || 0})
              </button>
              <button
                onClick={() => onSelectSource('NVD_NIST')}
                className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-all ${
                  selectedSource === 'NVD_NIST'
                    ? 'bg-blue-500/20 text-blue-300 border border-blue-500/50'
                    : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                }`}
              >
                NVD NIST ({stats.sourcesBreakdown.NVD_NIST || 0})
              </button>
            </div>
          </div>
        </div>

        {/* Footer info */}
        <div className="mt-4 pt-3 border-t border-slate-800 text-[11px] text-slate-400 flex items-center justify-between">
          <span>استاندارد نمره‌دهی: CVSS v3.1</span>
          <span className="text-emerald-400 font-medium">پایش لحظه‌ای فعال</span>
        </div>
      </div>

    </div>
  );
};
