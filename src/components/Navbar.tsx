import React from 'react';
import {
  ShieldAlert,
  Radio,
  RefreshCw,
  Terminal,
  Bookmark,
  Download,
  Flame,
} from 'lucide-react';
import { VulnerabilitySource } from '../types/vulnerability';

interface NavbarProps {
  isCrawling: boolean;
  onStartCrawl: (source?: VulnerabilitySource | 'ALL') => void;
  onOpenCrawlerDrawer: () => void;
  watchlistCount: number;
  onToggleWatchlistFilter: () => void;
  isWatchlistActive: boolean;
  onExportData: (format: 'json' | 'csv') => void;
  totalVulnerabilities: number;
  lastCrawlTime?: string;
}

export const Navbar: React.FC<NavbarProps> = ({
  isCrawling,
  onStartCrawl,
  onOpenCrawlerDrawer,
  watchlistCount,
  onToggleWatchlistFilter,
  isWatchlistActive,
  onExportData,
  totalVulnerabilities,
  lastCrawlTime,
}) => {
  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-800 bg-slate-950/90 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16 gap-4">
          
          {/* Logo & Platform Name */}
          <div className="flex items-center gap-3">
            <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-tr from-rose-600 via-rose-500 to-amber-500 shadow-lg shadow-rose-950/40 border border-rose-400/30">
              <ShieldAlert className="w-6 h-6 text-white" />
              <span className="absolute -top-1 -right-1 flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-3 w-3 bg-rose-500"></span>
              </span>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xl font-black tracking-tight text-white font-mono">
                  Vuln<span className="text-rose-500">Hunter</span>
                </span>
                <span className="px-2 py-0.5 text-[10px] font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30 rounded-full">
                  SOC رصد
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                سامانه پایش و کراولر آسیب‌پذیری‌های امنیتی از مراجع رسمی
              </p>
            </div>
          </div>

          {/* Crawler Status Pill */}
          <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs">
            <div className="flex items-center gap-2">
              <span className={`inline-block w-2.5 h-2.5 rounded-full ${isCrawling ? 'bg-amber-400 animate-pulse' : 'bg-emerald-400'}`} />
              <span className="text-slate-300 font-medium">
                {isCrawling ? 'در حال خزش مراجع...' : 'کراولر آماده به کار'}
              </span>
            </div>
            {lastCrawlTime && (
              <span className="text-slate-400 font-mono text-[11px] border-r border-slate-800 pr-2 mr-1">
                آخرین بروزرسانی: {new Date(lastCrawlTime).toLocaleTimeString('fa-IR')}
              </span>
            )}
          </div>

          {/* Actions & Crawl Controls */}
          <div className="flex items-center gap-2 sm:gap-3">
            
            {/* Watchlist Filter Button */}
            <button
              onClick={onToggleWatchlistFilter}
              className={`relative flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                isWatchlistActive
                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/50 shadow-sm shadow-amber-950'
                  : 'bg-slate-900 text-slate-300 border border-slate-800 hover:bg-slate-800 hover:text-white'
              }`}
              title="نمایش آسیب‌پذیری‌های تحت نظر"
            >
              <Bookmark className={`w-3.5 h-3.5 ${isWatchlistActive ? 'fill-amber-400 text-amber-400' : ''}`} />
              <span className="hidden sm:inline">تحت نظر</span>
              {watchlistCount > 0 && (
                <span className="px-1.5 py-0.2 rounded-full bg-amber-500/30 text-amber-300 font-mono text-[10px]">
                  {watchlistCount}
                </span>
              )}
            </button>

            {/* Terminal / Logs Drawer Trigger */}
            <button
              onClick={onOpenCrawlerDrawer}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-900 text-slate-300 border border-slate-800 hover:bg-slate-800 hover:text-white transition-all"
              title="کنسول و تنظیمات کراولر"
            >
              <Terminal className="w-3.5 h-3.5 text-cyan-400" />
              <span className="hidden sm:inline">کنسول خزش</span>
            </button>

            {/* Export Dropdown */}
            <div className="relative group">
              <button
                className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-medium bg-slate-900 text-slate-300 border border-slate-800 hover:bg-slate-800 transition-all"
                title="خروجی داده‌ها"
              >
                <Download className="w-3.5 h-3.5" />
                <span className="hidden md:inline">خروجی</span>
              </button>
              <div className="absolute left-0 mt-1 w-32 bg-slate-900 border border-slate-800 rounded-lg shadow-xl opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all py-1 z-50">
                <button
                  onClick={() => onExportData('json')}
                  className="w-full text-right px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 hover:text-white"
                >
                  دریافت JSON
                </button>
                <button
                  onClick={() => onExportData('csv')}
                  className="w-full text-right px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 hover:text-white"
                >
                  دریافت CSV
                </button>
              </div>
            </div>

            {/* Primary Action: Trigger Crawl */}
            <button
              onClick={() => onStartCrawl('ALL')}
              disabled={isCrawling}
              className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-bold text-white bg-gradient-to-r from-rose-600 to-rose-700 hover:from-rose-500 hover:to-rose-600 active:scale-95 transition-all shadow-md shadow-rose-900/30 border border-rose-500/40 disabled:opacity-50 disabled:pointer-events-none"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isCrawling ? 'animate-spin' : ''}`} />
              <span>{isCrawling ? 'در حال خزش...' : 'شروع کراول'}</span>
            </button>

          </div>

        </div>
      </div>
    </header>
  );
};
