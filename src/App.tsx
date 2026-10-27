import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { Navbar } from './components/Navbar';
import { MetricsHud } from './components/MetricsHud';
import { VisualCharts } from './components/VisualCharts';
import { VulnerabilityFilters } from './components/VulnerabilityFilters';
import { VulnerabilityCard } from './components/VulnerabilityCard';
import { VulnerabilityTable } from './components/VulnerabilityTable';
import { VulnerabilityDetailModal } from './components/VulnerabilityDetailModal';
import { CrawlerDrawer } from './components/CrawlerDrawer';
import {
  Vulnerability,
  CrawlStats,
  CrawlLog,
  CrawlSourceConfig,
  CrawlFilterOptions,
  VulnerabilitySource,
  VulnerabilityStatus,
} from './types/vulnerability';
import {
  computeVulnerabilityStats,
  filterAndSortVulnerabilities,
} from './utils/crawler-parser';
import { SEED_VULNERABILITIES, OFFICIAL_SOURCES } from './data/seed-vulnerabilities';
import { Shield, RefreshCw, AlertCircle, CheckCircle, Flame } from 'lucide-react';

export default function App() {
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>(SEED_VULNERABILITIES);
  const [sources, setSources] = useState<CrawlSourceConfig[]>(OFFICIAL_SOURCES);
  const [logs, setLogs] = useState<CrawlLog[]>([]);
  const [isCrawling, setIsCrawling] = useState(false);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [viewMode, setViewMode] = useState<'grid' | 'table'>('grid');
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'info' | 'error' } | null>(null);
  const [lastCrawlTime, setLastCrawlTime] = useState<string>(new Date().toISOString());

  // Filters State
  const [filters, setFilters] = useState<CrawlFilterOptions>({
    searchQuery: '',
    severity: 'ALL',
    source: 'ALL',
    vendor: undefined,
    onlyExploited: false,
    onlyRansomware: false,
    status: 'ALL',
    sortBy: 'date_desc',
  });

  const showToast = useCallback((message: string, type: 'success' | 'info' | 'error' = 'info') => {
    setToast({ message, type });
    setTimeout(() => {
      setToast(null);
    }, 4000);
  }, []);

  // Fetch initial data from server
  const loadData = useCallback(async () => {
    try {
      const [vulnsRes, sourcesRes, logsRes] = await Promise.allSettled([
        fetch('/api/vulnerabilities'),
        fetch('/api/sources'),
        fetch('/api/crawl/logs'),
      ]);

      if (vulnsRes.status === 'fulfilled' && vulnsRes.value.ok) {
        const data = await vulnsRes.value.json();
        if (data.vulnerabilities && data.vulnerabilities.length > 0) {
          setVulnerabilities(data.vulnerabilities);
        }
      }

      if (sourcesRes.status === 'fulfilled' && sourcesRes.value.ok) {
        const sourcesData = await sourcesRes.value.json();
        if (Array.isArray(sourcesData) && sourcesData.length > 0) {
          setSources(sourcesData);
        }
      }

      if (logsRes.status === 'fulfilled' && logsRes.value.ok) {
        const logsData = await logsRes.value.json();
        if (Array.isArray(logsData)) {
          setLogs(logsData);
        }
      }
    } catch (err) {
      console.warn('Initial load fallback to seed intelligence data');
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Compute live stats based on current vulnerability store
  const stats: CrawlStats = useMemo(() => {
    return computeVulnerabilityStats(vulnerabilities, lastCrawlTime);
  }, [vulnerabilities, lastCrawlTime]);

  // Filter and sort items for display
  const filteredVulnerabilities = useMemo(() => {
    return filterAndSortVulnerabilities(vulnerabilities, filters);
  }, [vulnerabilities, filters]);

  // Watchlist count
  const watchlistCount = useMemo(() => {
    return vulnerabilities.filter((v) => v.status === 'watching').length;
  }, [vulnerabilities]);

  // Handle live crawl trigger
  const handleStartCrawl = async (source: VulnerabilitySource | 'ALL' = 'ALL') => {
    if (isCrawling) return;
    setIsCrawling(true);
    showToast('در حال شروع خزش مراجع رسمی امنیتی (CISA KEV, GitHub, NVD)...', 'info');

    try {
      const response = await fetch('/api/crawl', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `خطا در اجرای کراولر: ${response.status}`);
      }

      const result = await response.json();
      showToast(
        `خزش با موفقیت انجام شد: ${result.crawledCount} رکورد بررسی و ${result.newItemsAdded} آسیب‌پذیری جدید به سامانه افزوده شد.`,
        'success'
      );

      if (result.lastCrawlTime) {
        setLastCrawlTime(result.lastCrawlTime);
      }

      // Reload fresh data from server
      await loadData();
    } catch (error: any) {
      console.error('Crawl execution error:', error);
      showToast(`خطا در ارتباط با سرور کراول: ${error.message}`, 'error');
    } finally {
      setIsCrawling(false);
    }
  };

  // Toggle vulnerability status (active / watching / resolved)
  const handleToggleStatus = async (id: string, status: VulnerabilityStatus) => {
    // Optimistic UI update
    setVulnerabilities((prev) =>
      prev.map((v) => (v.id.toLowerCase() === id.toLowerCase() ? { ...v, status } : v))
    );

    if (selectedVuln && selectedVuln.id.toLowerCase() === id.toLowerCase()) {
      setSelectedVuln((prev) => (prev ? { ...prev, status } : null));
    }

    try {
      await fetch(`/api/vulnerabilities/${encodeURIComponent(id)}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status }),
      });
      showToast(
        status === 'watching'
          ? `آسیب‌پذیری ${id} به لیست تحت نظر افزوده شد.`
          : status === 'resolved'
          ? `آسیب‌پذیری ${id} به عنوان رفع‌شده ثبت شد.`
          : `وضعیت آسیب‌پذیری ${id} به فعال تغییر کرد.`,
        'info'
      );
    } catch (err) {
      console.warn('Status patch note:', err);
    }
  };

  // Toggle source in crawler
  const handleToggleSource = async (id: VulnerabilitySource) => {
    setSources((prev) =>
      prev.map((s) => (s.id === id ? { ...s, enabled: !s.enabled } : s))
    );
    try {
      await fetch(`/api/sources/${id}/toggle`, { method: 'POST' });
    } catch (err) {
      console.warn('Source toggle error:', err);
    }
  };

  // Trigger AI Threat Analysis
  const handleAnalyzeAi = async (id: string) => {
    setIsAnalyzing(true);
    try {
      const res = await fetch(`/api/analyze/${encodeURIComponent(id)}`, {
        method: 'POST',
      });
      if (res.ok) {
        const data = await res.json();
        if (data.aiSummary) {
          setVulnerabilities((prev) =>
            prev.map((v) =>
              v.id.toLowerCase() === id.toLowerCase() ? { ...v, aiSummary: data.aiSummary } : v
            )
          );
          if (selectedVuln && selectedVuln.id.toLowerCase() === id.toLowerCase()) {
            setSelectedVuln((prev) => (prev ? { ...prev, aiSummary: data.aiSummary } : null));
          }
          showToast('تحلیل هوشمند امنیتی با موفقیت بروزرسانی شد.', 'success');
        }
      }
    } catch (err: any) {
      showToast('خطا در دریافت تحلیل هوشمند', 'error');
    } finally {
      setIsAnalyzing(false);
    }
  };

  // Export Data to JSON or CSV
  const handleExportData = (format: 'json' | 'csv') => {
    const dataToExport = filteredVulnerabilities;
    if (format === 'json') {
      const blob = new Blob([JSON.stringify(dataToExport, null, 2)], {
        type: 'application/json',
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `vulnhunter-export-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } else {
      const headers = ['ID', 'Severity', 'CVSS', 'Vendor', 'Product', 'Title', 'Exploited', 'Published'];
      const rows = dataToExport.map((v) => [
        `"${v.id}"`,
        `"${v.severity}"`,
        v.cvssScore,
        `"${v.affectedVendor.replace(/"/g, '""')}"`,
        `"${v.affectedProduct.replace(/"/g, '""')}"`,
        `"${v.title.replace(/"/g, '""')}"`,
        v.isKnownExploited ? 'YES' : 'NO',
        `"${v.publishedDate}"`,
      ]);
      const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `vulnhunter-export-${new Date().toISOString().slice(0, 10)}.csv`;
      a.click();
      URL.revokeObjectURL(url);
    }
    showToast(`فایل خروجی ${format.toUpperCase()} با موفقیت آماده و دانلود شد.`, 'success');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      
      {/* Toast Notification */}
      {toast && (
        <div
          role="status"
          className={`fixed bottom-6 left-6 z-50 flex items-center gap-2.5 px-4 py-3 rounded-xl shadow-2xl border text-xs font-medium animate-bounce ${
            toast.type === 'success'
              ? 'bg-emerald-950 text-emerald-200 border-emerald-500/50'
              : toast.type === 'error'
              ? 'bg-rose-950 text-rose-200 border-rose-500/50'
              : 'bg-slate-900 text-slate-200 border-slate-700'
          }`}
        >
          {toast.type === 'success' ? (
            <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
          ) : toast.type === 'error' ? (
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
          ) : (
            <Shield className="w-4 h-4 text-cyan-400 shrink-0" />
          )}
          <span>{toast.message}</span>
        </div>
      )}

      {/* Top Navbar */}
      <Navbar
        isCrawling={isCrawling}
        onStartCrawl={handleStartCrawl}
        onOpenCrawlerDrawer={() => setIsDrawerOpen(true)}
        watchlistCount={watchlistCount}
        onToggleWatchlistFilter={() =>
          setFilters((prev) => ({
            ...prev,
            status: prev.status === 'watching' ? 'ALL' : 'watching',
          }))
        }
        isWatchlistActive={filters.status === 'watching'}
        onExportData={handleExportData}
        totalVulnerabilities={vulnerabilities.length}
        lastCrawlTime={lastCrawlTime}
      />

      {/* Main Dashboard Body */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        
        {/* Banner with Live Crawl Status */}
        <div className="relative mb-6 p-4 sm:p-5 rounded-2xl bg-gradient-to-r from-slate-900 via-rose-950/20 to-slate-900 border border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-rose-500/20 text-rose-300 border border-rose-500/40">
                LIVE CRAWLER ACTIVE
              </span>
              <span className="text-xs text-slate-400">
                اتصال مستقیم به منابع رسمی CISA KEV، GitHub Advisory، NVD NIST
              </span>
            </div>
            <h1 className="text-lg sm:text-xl font-black text-white">
              دیده‌بان و پایگاه پایش آسیب‌پذیری‌های سایبری
            </h1>
          </div>

          <div className="flex items-center gap-2 self-stretch sm:self-auto justify-end">
            <button
              onClick={() => handleStartCrawl('ALL')}
              disabled={isCrawling}
              className="flex-1 sm:flex-initial px-4 py-2 rounded-xl text-xs font-bold text-white bg-rose-600 hover:bg-rose-500 active:scale-95 transition-all shadow-lg shadow-rose-950/50 flex items-center justify-center gap-2 disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 ${isCrawling ? 'animate-spin' : ''}`} />
              <span>{isCrawling ? 'در حال خزش...' : 'خزش و بروزرسانی لحظه‌ای مراجع'}</span>
            </button>
          </div>
        </div>

        {/* 1. Metrics HUD */}
        <MetricsHud
          stats={stats}
          onFilterBySeverity={(sev) =>
            setFilters((prev) => ({
              ...prev,
              severity: prev.severity === sev ? 'ALL' : sev,
            }))
          }
          onFilterExploited={() =>
            setFilters((prev) => ({
              ...prev,
              onlyExploited: !prev.onlyExploited,
            }))
          }
          onFilterRansomware={() =>
            setFilters((prev) => ({
              ...prev,
              onlyRansomware: !prev.onlyRansomware,
            }))
          }
        />

        {/* 2. Visual Charts (Severity spectrum, Top Vendors, Attack Vectors) */}
        <VisualCharts
          stats={stats}
          selectedVendor={filters.vendor}
          onSelectVendor={(vendor) => setFilters((prev) => ({ ...prev, vendor }))}
          selectedSource={filters.source}
          onSelectSource={(source) => setFilters((prev) => ({ ...prev, source }))}
        />

        {/* 3. Search & Interactive Filter Bar */}
        <VulnerabilityFilters
          filters={filters}
          onChange={(updated) => setFilters((prev) => ({ ...prev, ...updated }))}
          onReset={() =>
            setFilters({
              searchQuery: '',
              severity: 'ALL',
              source: 'ALL',
              vendor: undefined,
              onlyExploited: false,
              onlyRansomware: false,
              status: 'ALL',
              sortBy: 'date_desc',
            })
          }
          totalFiltered={filteredVulnerabilities.length}
          viewMode={viewMode}
          onChangeViewMode={setViewMode}
        />

        {/* 4. Vulnerabilities Content (Grid or Table View) */}
        {viewMode === 'grid' ? (
          filteredVulnerabilities.length === 0 ? (
            <div className="p-12 text-center bg-slate-900/60 rounded-2xl border border-slate-800 text-slate-400">
              <Shield className="w-10 h-10 mx-auto text-slate-400 mb-3" />
              <p className="text-base font-semibold text-slate-300">هیچ آسیب‌پذیری با فیلترهای جاری مطابقت ندارد.</p>
              <p className="text-xs text-slate-400 mt-1">می‌توانید عبارت جستجو را تغییر دهید یا دکمه «شروع کراول» را بزنید.</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {filteredVulnerabilities.map((vuln) => (
                <VulnerabilityCard
                  key={vuln.id}
                  vulnerability={vuln}
                  onSelect={(v) => setSelectedVuln(v)}
                  onToggleStatus={handleToggleStatus}
                />
              ))}
            </div>
          )
        ) : (
          <VulnerabilityTable
            vulnerabilities={filteredVulnerabilities}
            onSelect={(v) => setSelectedVuln(v)}
            onToggleStatus={handleToggleStatus}
          />
        )}

      </main>

      {/* Detail Modal / Threat Dossier */}
      <VulnerabilityDetailModal
        vulnerability={selectedVuln}
        onClose={() => setSelectedVuln(null)}
        onToggleStatus={handleToggleStatus}
        onAnalyzeAi={handleAnalyzeAi}
        isAnalyzing={isAnalyzing}
      />

      {/* Crawler Console Drawer */}
      <CrawlerDrawer
        isOpen={isDrawerOpen}
        onClose={() => setIsDrawerOpen(false)}
        sources={sources}
        onToggleSource={handleToggleSource}
        logs={logs}
        isCrawling={isCrawling}
        onTriggerCrawl={handleStartCrawl}
      />

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-6 mt-12 text-center text-xs text-slate-400">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="font-mono font-bold text-slate-300">VulnHunter Threat Platform</span>
            <span>—</span>
            <span>کرالر و سامانه تحلیل آسیب‌پذیری‌های امنیتی</span>
          </div>
          <div className="flex items-center gap-4 text-slate-400 font-mono text-[11px]">
            <span>CISA KEV</span>
            <span>•</span>
            <span>NIST NVD</span>
            <span>•</span>
            <span>GitHub Advisories</span>
            <span>•</span>
            <span>OSV</span>
          </div>
        </div>
      </footer>

    </div>
  );
}
