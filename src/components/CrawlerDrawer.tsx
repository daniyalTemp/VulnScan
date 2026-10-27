import React from 'react';
import {
  X,
  Terminal,
  RefreshCw,
  ExternalLink,
  CheckCircle,
  AlertCircle,
  Clock,
  Database,
  Radio,
  Sliders,
} from 'lucide-react';
import { CrawlLog, CrawlSourceConfig, VulnerabilitySource } from '../types/vulnerability';

interface CrawlerDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  sources: CrawlSourceConfig[];
  onToggleSource: (id: VulnerabilitySource) => void;
  logs: CrawlLog[];
  isCrawling: boolean;
  onTriggerCrawl: (source: VulnerabilitySource | 'ALL') => void;
}

export const CrawlerDrawer: React.FC<CrawlerDrawerProps> = ({
  isOpen,
  onClose,
  sources,
  onToggleSource,
  logs,
  isCrawling,
  onTriggerCrawl,
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/70 backdrop-blur-sm transition-opacity">
      <div className="w-full max-w-2xl bg-slate-950 border-r lg:border-l border-slate-800 h-full flex flex-col shadow-2xl overflow-hidden">
        
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-slate-800 bg-slate-900/60">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/20">
              <Terminal className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                کنسول مدیریت و خزش مراجع رسمی
                <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-300">
                  Crawler Core
                </span>
              </h2>
              <p className="text-xs text-slate-400">
                تنظیم مراجع، واکشی آنلاین و مشاهده لاگ‌های اجرای لحظه‌ای
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-4 space-y-6">
          
          {/* 1. Quick Crawl Controls & Scheduler Settings */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
              <div>
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <RefreshCw className={`w-4 h-4 text-rose-500 ${isCrawling ? 'animate-spin' : ''}`} />
                  اجرای خزش دستی فوری
                </h3>
                <p className="text-xs text-slate-400">
                  دریافت آنلاین آسیب‌پذیری‌های جدید به درخواست کاربر
                </p>
              </div>
              <button
                onClick={() => onTriggerCrawl('ALL')}
                disabled={isCrawling}
                className="w-full sm:w-auto px-4 py-2 rounded-lg text-xs font-bold text-white bg-rose-600 hover:bg-rose-500 transition-all flex items-center justify-center gap-2 disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isCrawling ? 'animate-spin' : ''}`} />
                <span>{isCrawling ? 'در حال خزش...' : 'خزش همه منابع (Crawl All)'}</span>
              </button>
            </div>

            {/* Scheduler Interval Selection */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                  <Clock className="w-3.5 h-3.5 text-cyan-400" />
                  زمان‌بندی خزش خودکار (Auto-Crawl Scheduler):
                </span>
                <span className="text-[11px] font-mono text-emerald-400">
                  اجرا در پس‌زمینه سرور
                </span>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                <button
                  onClick={async () => {
                    await fetch('/api/schedule', {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ autoCrawlEnabled: true, crawlIntervalMinutes: 60 }),
                    });
                  }}
                  className="p-2 rounded-lg bg-slate-950 border border-slate-800 hover:border-cyan-500/50 text-right transition-colors"
                >
                  <span className="block font-bold text-white">هر ۱ ساعت</span>
                  <span className="text-[10px] text-slate-400">پیش‌فرض پایش</span>
                </button>

                <button
                  onClick={async () => {
                    await fetch('/api/schedule', {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ autoCrawlEnabled: true, crawlIntervalMinutes: 360 }),
                    });
                  }}
                  className="p-2 rounded-lg bg-slate-950 border border-slate-800 hover:border-cyan-500/50 text-right transition-colors"
                >
                  <span className="block font-bold text-white">هر ۶ ساعت</span>
                  <span className="text-[10px] text-slate-400">مناسب شبکه داخلی</span>
                </button>

                <button
                  onClick={async () => {
                    await fetch('/api/schedule', {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ autoCrawlEnabled: true, crawlIntervalMinutes: 1440 }),
                    });
                  }}
                  className="p-2 rounded-lg bg-slate-950 border border-slate-800 hover:border-cyan-500/50 text-right transition-colors"
                >
                  <span className="block font-bold text-white">روزانه (۲۴ ساعت)</span>
                  <span className="text-[10px] text-slate-400">گزارش روزانه</span>
                </button>

                <button
                  onClick={async () => {
                    await fetch('/api/schedule', {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ autoCrawlEnabled: false, crawlIntervalMinutes: 0 }),
                    });
                  }}
                  className="p-2 rounded-lg bg-slate-950 border border-slate-800 hover:border-rose-500/50 text-right transition-colors"
                >
                  <span className="block font-bold text-amber-400">فقط به درخواست کاربر</span>
                  <span className="text-[10px] text-slate-400">دستی (Manual)</span>
                </button>
              </div>
            </div>
          </div>

          {/* 2. Official Sources Config */}
          <div>
            <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
              <Database className="w-3.5 h-3.5 text-cyan-400" />
              مراجع رسمی متصل به کراولر
            </h3>

            <div className="space-y-3">
              {sources.map((src) => (
                <div
                  key={src.id}
                  className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800/90 hover:border-slate-700 transition-all"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <span className="text-sm font-bold text-white">{src.nameFa}</span>
                        <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border ${src.badgeColor}`}>
                          {src.name}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 mb-2 leading-relaxed">
                        {src.descriptionFa}
                      </p>
                      <div className="flex items-center gap-3 text-[11px] text-slate-400 font-mono">
                        <a
                          href={src.url}
                          target="_blank"
                          rel="noreferrer"
                          className="flex items-center gap-1 text-cyan-400 hover:underline"
                        >
                          مشاهده تارنما
                          <ExternalLink className="w-3 h-3" />
                        </a>
                        <span>•</span>
                        <span>پروتکل: JSON REST / Feed</span>
                      </div>
                    </div>

                    <div className="flex flex-col items-end gap-2">
                      <button
                        onClick={() => onTriggerCrawl(src.id)}
                        disabled={isCrawling}
                        className="px-2.5 py-1 text-xs rounded bg-slate-800 text-slate-200 hover:bg-slate-700 disabled:opacity-40 transition-colors"
                      >
                        خزش تک‌منبع
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* 3. Real-time Crawl Terminal & Activity Logs */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                کنسول لاگ‌ها و رخدادهای کراولر
              </h3>
              <span className="text-[11px] font-mono text-slate-400">
                {logs.length} رکورد ثبت‌شده
              </span>
            </div>

            {/* Terminal Box */}
            <div className="bg-slate-950 rounded-xl border border-slate-800/90 p-3 font-mono text-xs overflow-hidden">
              <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-900 text-[11px] text-slate-400">
                <div className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-rose-500/80 inline-block" />
                  <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80 inline-block" />
                  <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80 inline-block" />
                  <span className="text-slate-400 mr-2">vulnhunter-crawler.log</span>
                </div>
                <span>STATUS: OK</span>
              </div>

              <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                {logs.length === 0 ? (
                  <p className="text-slate-400 italic">هیچ رخدادی هنوز ثبت نشده است.</p>
                ) : (
                  logs.map((log) => (
                    <div
                      key={log.id}
                      className="p-2 rounded bg-slate-900/60 border border-slate-800/50 flex flex-col gap-1 text-[11px]"
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-slate-400 flex items-center gap-1 font-mono">
                          <Clock className="w-3 h-3" />
                          {new Date(log.timestamp).toLocaleTimeString('fa-IR')}
                        </span>
                        <div className="flex items-center gap-1.5">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] uppercase font-bold ${
                              log.status === 'success'
                                ? 'bg-emerald-500/20 text-emerald-400'
                                : log.status === 'warning'
                                ? 'bg-amber-500/20 text-amber-400'
                                : 'bg-rose-500/20 text-rose-400'
                            }`}
                          >
                            {log.status}
                          </span>
                          <span className="text-slate-400 font-mono">{log.durationMs}ms</span>
                        </div>
                      </div>

                      <div className="text-slate-200 leading-relaxed">
                        <span className="text-rose-400 font-bold ml-1">[{log.sourceLabel}]</span>
                        {log.message}
                      </div>

                      {log.newItemsAdded > 0 && (
                        <div className="text-emerald-400 text-[10px]">
                          + {log.newItemsAdded} آسیب‌پذیری جدید به بانک اطلاعاتی اضافه شد.
                        </div>
                      )}
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/40 flex items-center justify-between text-xs text-slate-400">
          <span>کراولر خودکار با پشتیبانی از پروتکل‌های امنیتی CISA و NIST</span>
          <button
            onClick={onClose}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-white transition-colors"
          >
            بستن کنسول
          </button>
        </div>

      </div>
    </div>
  );
};
