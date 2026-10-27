import {
  Vulnerability,
  VulnerabilitySource,
  SeverityLevel,
  CrawlStats,
  CrawlFilterOptions,
} from '../types/vulnerability';

/**
 * Normalizes severity into standard CRITICAL, HIGH, MEDIUM, LOW levels
 */
export function normalizeSeverity(score?: number, text?: string): SeverityLevel {
  if (score !== undefined && score !== null && !isNaN(score)) {
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    if (score > 0) return 'LOW';
  }

  if (text) {
    const upper = text.toUpperCase().trim();
    if (upper.includes('CRIT')) return 'CRITICAL';
    if (upper.includes('HIGH')) return 'HIGH';
    if (upper.includes('MED')) return 'MEDIUM';
    if (upper.includes('LOW')) return 'LOW';
  }

  return 'UNKNOWN';
}

/**
 * Extracts CVSS components from CVSS v3.1 vector string
 * e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
 */
export function parseCvssVector(vector?: string): {
  attackVector: 'NETWORK' | 'ADJACENT' | 'LOCAL' | 'PHYSICAL' | 'UNKNOWN';
  attackComplexity?: 'LOW' | 'HIGH';
  privilegesRequired?: 'NONE' | 'LOW' | 'HIGH';
  userInteraction?: 'NONE' | 'REQUIRED';
} {
  if (!vector || typeof vector !== 'string') {
    return { attackVector: 'UNKNOWN' };
  }

  const parts = vector.split('/');
  const map: Record<string, string> = {};
  for (const part of parts) {
    const [key, val] = part.split(':');
    if (key && val) {
      map[key.toUpperCase()] = val.toUpperCase();
    }
  }

  let attackVector: 'NETWORK' | 'ADJACENT' | 'LOCAL' | 'PHYSICAL' | 'UNKNOWN' = 'UNKNOWN';
  if (map['AV'] === 'N') attackVector = 'NETWORK';
  else if (map['AV'] === 'A') attackVector = 'ADJACENT';
  else if (map['AV'] === 'L') attackVector = 'LOCAL';
  else if (map['AV'] === 'P') attackVector = 'PHYSICAL';

  let attackComplexity: 'LOW' | 'HIGH' | undefined;
  if (map['AC'] === 'L') attackComplexity = 'LOW';
  else if (map['AC'] === 'H') attackComplexity = 'HIGH';

  let privilegesRequired: 'NONE' | 'LOW' | 'HIGH' | undefined;
  if (map['PR'] === 'N') privilegesRequired = 'NONE';
  else if (map['PR'] === 'L') privilegesRequired = 'LOW';
  else if (map['PR'] === 'H') privilegesRequired = 'HIGH';

  let userInteraction: 'NONE' | 'REQUIRED' | undefined;
  if (map['UI'] === 'N') userInteraction = 'NONE';
  else if (map['UI'] === 'R') userInteraction = 'REQUIRED';

  return {
    attackVector,
    attackComplexity,
    privilegesRequired,
    userInteraction,
  };
}

/**
 * Parses CISA KEV (Known Exploited Vulnerabilities) JSON feed
 */
export function parseCisaKevFeed(rawJson: any): Vulnerability[] {
  if (!rawJson || !Array.isArray(rawJson.vulnerabilities)) {
    return [];
  }

  const list: Vulnerability[] = [];

  for (const item of rawJson.vulnerabilities) {
    if (!item.cveID) continue;

    const ransomwareRaw = typeof item.knownRansomwareCampaignUse === 'string' 
      ? item.knownRansomwareCampaignUse.trim().toLowerCase() 
      : '';
    const hasRansomware = ransomwareRaw === 'known' || (ransomwareRaw.includes('known') && !ransomwareRaw.includes('unknown'));

    const cweIds = Array.isArray(item.cwes)
      ? item.cwes
      : typeof item.cwes === 'string' && item.cwes.length > 0
      ? [item.cwes]
      : [];

    list.push({
      id: item.cveID,
      title: item.vulnerabilityName || `${item.vendorProject || 'Vendor'} ${item.product || 'Product'} Vulnerability`,
      description: item.shortDescription || 'No description provided by CISA catalog.',
      source: 'CISA_KEV',
      sourceNameFa: 'کاتالوگ CISA KEV (به‌کارگیری فعال در حملات)',
      sourceUrl: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(
        item.cveID
      )}`,
      severity: 'CRITICAL', // CISA KEV vulnerabilities are actively exploited in the wild, treated with maximum urgency
      cvssScore: 9.2, // Default high base score for in-the-wild exploited CVEs if score is missing
      cweIds,
      affectedVendor: item.vendorProject || 'نامشخص',
      affectedProduct: item.product || 'نامشخص',
      affectedVersions: 'نسخه‌های اعلام شده توسط مراجع رسمی',
      publishedDate: item.dateAdded ? new Date(item.dateAdded).toISOString() : new Date().toISOString(),
      updatedDate: item.dateAdded ? new Date(item.dateAdded).toISOString() : new Date().toISOString(),
      isKnownExploited: true,
      hasRansomwareCampaign: hasRansomware,
      remediationAction: item.requiredAction || 'اعمال فوری وصله امنیتی توصیه شده یا قطع دسترسی شبکه به سرویس آسیب‌پذیر.',
      dueDate: item.dueDate || undefined,
      patchAvailable: true,
      attackVector: 'NETWORK',
      status: 'active',
      references: [
        {
          title: 'CISA KEV Catalog Reference',
          url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(item.cveID)}`,
        },
      ],
    });
  }

  return list;
}

/**
 * Parses GitHub Advisory Database JSON response
 */
export function parseGitHubAdvisoryFeed(rawList: any): Vulnerability[] {
  if (!Array.isArray(rawList)) {
    return [];
  }

  const list: Vulnerability[] = [];

  for (const item of rawList) {
    const id = item.cve_id || item.ghsa_id;
    if (!id) continue;

    const cvssScore = item.cvss?.score || (item.severity === 'critical' ? 9.5 : item.severity === 'high' ? 7.8 : item.severity === 'medium' ? 5.5 : 3.0);
    const cvssVector = item.cvss?.vector_string || undefined;
    const { attackVector, attackComplexity, privilegesRequired, userInteraction } = parseCvssVector(cvssVector);

    const cweIds: string[] = [];
    if (Array.isArray(item.cwes)) {
      for (const c of item.cwes) {
        if (typeof c === 'string') cweIds.push(c);
        else if (c && c.cwe_id) cweIds.push(c.cwe_id);
      }
    }

    const firstVuln = Array.isArray(item.vulnerabilities) && item.vulnerabilities[0];
    const pkg = firstVuln?.package?.name || 'کتابخانه نرم‌افزاری';
    const ecosystem = firstVuln?.package?.ecosystem || 'Open Source';

    const references: { title: string; url: string }[] = [];
    if (Array.isArray(item.references)) {
      for (const ref of item.references) {
        const url = typeof ref === 'string' ? ref : ref?.url;
        if (url) references.push({ title: 'Advisory Link', url });
      }
    }
    if (item.html_url) {
      references.unshift({ title: 'GitHub Security Advisory', url: item.html_url });
    }

    list.push({
      id,
      title: item.summary || `${pkg} (${ecosystem}) Security Advisory`,
      description: item.description || item.summary || 'توضیحات توسط گیت‌هاب ادوایزری ثبت نشده است.',
      source: 'GITHUB_ADVISORY',
      sourceNameFa: 'پایگاه رخدادهای امنیتی GitHub',
      sourceUrl: item.html_url || `https://github.com/advisories/${id}`,
      severity: normalizeSeverity(cvssScore, item.severity),
      cvssScore: Number(Number(cvssScore).toFixed(1)),
      cvssVector,
      cweIds,
      affectedVendor: ecosystem,
      affectedProduct: pkg,
      affectedVersions: firstVuln?.vulnerable_version_range || 'مشخص شده در ادوایزری',
      publishedDate: item.published_at ? new Date(item.published_at).toISOString() : new Date().toISOString(),
      updatedDate: item.updated_at ? new Date(item.updated_at).toISOString() : new Date().toISOString(),
      isKnownExploited: false,
      hasRansomwareCampaign: false,
      remediationAction: firstVuln?.patched_versions ? `ارتقا به نسخه امن: ${firstVuln.patched_versions}` : 'بروزرسانی پکیج به آخرین نسخه پایدار.',
      patchAvailable: Boolean(firstVuln?.patched_versions),
      attackVector,
      attackComplexity,
      privilegesRequired,
      userInteraction,
      status: 'active',
      references,
    });
  }

  return list;
}

/**
 * Parses NVD / NIST CVE 2.0 API JSON response
 */
export function parseNvdFeed(rawJson: any): Vulnerability[] {
  const items = rawJson?.vulnerabilities;
  if (!Array.isArray(items)) {
    return [];
  }

  const list: Vulnerability[] = [];

  for (const entry of items) {
    const cve = entry.cve;
    if (!cve || !cve.id) continue;

    // English description
    const descObj = cve.descriptions?.find((d: any) => d.lang === 'en') || cve.descriptions?.[0];
    const description = descObj?.value || 'No description provided.';

    // CVSS 3.1 or 3.0 metrics
    const metric31 = cve.metrics?.cvssMetricV31?.[0]?.cvssData || cve.metrics?.cvssMetricV30?.[0]?.cvssData;
    const cvssScore = metric31?.baseScore || 6.5;
    const cvssVector = metric31?.vectorString;
    const { attackVector, attackComplexity, privilegesRequired, userInteraction } = parseCvssVector(cvssVector);

    // Weaknesses / CWE
    const cweIds: string[] = [];
    if (Array.isArray(cve.weaknesses)) {
      for (const w of cve.weaknesses) {
        if (Array.isArray(w.description)) {
          for (const d of w.description) {
            if (d.value && d.value !== 'NVD-CWE-noinfo') {
              cweIds.push(d.value);
            }
          }
        }
      }
    }

    // References
    const references: { title: string; url: string }[] = [];
    if (Array.isArray(cve.references)) {
      for (const r of cve.references.slice(0, 5)) {
        if (r.url) {
          references.push({
            title: r.source || 'NVD Reference',
            url: r.url,
          });
        }
      }
    }

    // Guess vendor from configurations or description
    let vendor = 'گوناگون';
    let product = 'سیستم نرم‌افزاری';
    if (description.toLowerCase().includes('microsoft') || description.toLowerCase().includes('windows')) {
      vendor = 'Microsoft';
      product = 'Windows';
    } else if (description.toLowerCase().includes('linux') || description.toLowerCase().includes('kernel')) {
      vendor = 'Linux';
      product = 'Kernel';
    } else if (description.toLowerCase().includes('apache')) {
      vendor = 'Apache';
      product = 'Server/Framework';
    } else if (description.toLowerCase().includes('google') || description.toLowerCase().includes('chrome') || description.toLowerCase().includes('android')) {
      vendor = 'Google';
      product = 'Chrome/Android';
    } else if (description.toLowerCase().includes('apple') || description.toLowerCase().includes('ios') || description.toLowerCase().includes('macos')) {
      vendor = 'Apple';
      product = 'macOS/iOS';
    } else if (description.toLowerCase().includes('cisco')) {
      vendor = 'Cisco';
      product = 'IOS/Firmware';
    } else if (description.toLowerCase().includes('fortinet') || description.toLowerCase().includes('fortios')) {
      vendor = 'Fortinet';
      product = 'FortiOS';
    }

    list.push({
      id: cve.id,
      title: `${cve.id}: ${description.slice(0, 80)}...`,
      description,
      source: 'NVD_NIST',
      sourceNameFa: 'پایگاه ملی آسیب‌پذیری ایالات متحده (NIST NVD)',
      sourceUrl: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
      severity: normalizeSeverity(cvssScore, metric31?.baseSeverity),
      cvssScore: Number(Number(cvssScore).toFixed(1)),
      cvssVector,
      cweIds,
      affectedVendor: vendor,
      affectedProduct: product,
      affectedVersions: 'بر اساس بررسی پیکربندی NVD',
      publishedDate: cve.published ? new Date(cve.published).toISOString() : new Date().toISOString(),
      updatedDate: cve.lastModified ? new Date(cve.lastModified).toISOString() : new Date().toISOString(),
      isKnownExploited: false,
      hasRansomwareCampaign: false,
      remediationAction: 'اعمال آخرین وصله امنیتی توصیه شده توسط سازنده نرم‌افزار.',
      patchAvailable: true,
      attackVector,
      attackComplexity,
      privilegesRequired,
      userInteraction,
      status: 'active',
      references,
    });
  }

  return list;
}

/**
 * Deduplicates vulnerabilities by ID and merges enhanced fields
 */
export function deduplicateVulnerabilities(items: Vulnerability[]): Vulnerability[] {
  const map = new Map<string, Vulnerability>();

  for (const item of items) {
    const existing = map.get(item.id);
    if (!existing) {
      map.set(item.id, { ...item });
      continue;
    }

    // Merge: prefer higher severity or CISA KEV priority
    const isCisa = item.source === 'CISA_KEV' || existing.source === 'CISA_KEV';
    const isKnownExploited = item.isKnownExploited || existing.isKnownExploited;
    const hasRansomware = item.hasRansomwareCampaign || existing.hasRansomwareCampaign;
    const highestCvss = Math.max(item.cvssScore, existing.cvssScore);

    const mergedReferences = [...existing.references];
    for (const ref of item.references) {
      if (!mergedReferences.some((r) => r.url === ref.url)) {
        mergedReferences.push(ref);
      }
    }

    const mergedCwes = Array.from(new Set([...existing.cweIds, ...item.cweIds]));

    map.set(item.id, {
      ...existing,
      cvssScore: highestCvss,
      severity: normalizeSeverity(highestCvss),
      isKnownExploited,
      hasRansomwareCampaign: hasRansomware,
      cweIds: mergedCwes,
      references: mergedReferences,
      remediationAction: item.remediationAction || existing.remediationAction,
      dueDate: item.dueDate || existing.dueDate,
      source: isCisa ? 'CISA_KEV' : existing.source,
      sourceNameFa: isCisa ? 'کاتالوگ CISA KEV (به‌کارگیری فعال در حملات)' : existing.sourceNameFa,
    });
  }

  return Array.from(map.values());
}

/**
 * Computes live statistical metrics for dashboard visuals
 */
export function computeVulnerabilityStats(items: Vulnerability[], lastCrawlTime?: string): CrawlStats {
  let critical = 0;
  let high = 0;
  let medium = 0;
  let low = 0;
  let activelyExploited = 0;
  let ransomwareLinked = 0;
  let resolved = 0;
  let watching = 0;

  const vendorCounts: Record<string, number> = {};
  const cweCounts: Record<string, number> = {};
  const vectorCounts: Record<string, number> = {};
  const sourcesBreakdown: Record<VulnerabilitySource, number> = {
    CISA_KEV: 0,
    GITHUB_ADVISORY: 0,
    NVD_NIST: 0,
    OSV: 0,
    CUSTOM: 0,
  };

  for (const item of items) {
    if (item.severity === 'CRITICAL') critical++;
    else if (item.severity === 'HIGH') high++;
    else if (item.severity === 'MEDIUM') medium++;
    else if (item.severity === 'LOW') low++;

    if (item.isKnownExploited) activelyExploited++;
    if (item.hasRansomwareCampaign) ransomwareLinked++;
    if (item.status === 'resolved') resolved++;
    else if (item.status === 'watching') watching++;

    // Vendor stats
    const vendor = item.affectedVendor || 'Other';
    vendorCounts[vendor] = (vendorCounts[vendor] || 0) + 1;

    // CWE stats
    for (const cwe of item.cweIds) {
      cweCounts[cwe] = (cweCounts[cwe] || 0) + 1;
    }

    // Attack vector
    const vector = item.attackVector || 'UNKNOWN';
    vectorCounts[vector] = (vectorCounts[vector] || 0) + 1;

    // Sources breakdown
    if (sourcesBreakdown[item.source] !== undefined) {
      sourcesBreakdown[item.source]++;
    }
  }

  // Top 6 vendors sorted
  const topVendors = Object.entries(vendorCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([vendor, count]) => ({ vendor, count }));

  // Top 5 CWEs sorted
  const topCwes = Object.entries(cweCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([cwe, count]) => ({ cwe, count }));

  // Attack vectors
  const attackVectors = Object.entries(vectorCounts)
    .sort((a, b) => b[1] - a[1])
    .map(([vector, count]) => ({ vector, count }));

  return {
    total: items.length,
    critical,
    high,
    medium,
    low,
    activelyExploited,
    ransomwareLinked,
    resolved,
    watching,
    topVendors,
    topCwes,
    sourcesBreakdown,
    attackVectors,
    lastCrawlTime,
  };
}

/**
 * Filter and sort vulnerabilities
 */
export function filterAndSortVulnerabilities(
  items: Vulnerability[],
  options: CrawlFilterOptions
): Vulnerability[] {
  let filtered = [...items];

  // Search filter
  if (options.searchQuery && options.searchQuery.trim() !== '') {
    const q = options.searchQuery.toLowerCase().trim();
    filtered = filtered.filter(
      (v) =>
        v.id.toLowerCase().includes(q) ||
        v.title.toLowerCase().includes(q) ||
        v.description.toLowerCase().includes(q) ||
        v.affectedVendor.toLowerCase().includes(q) ||
        v.affectedProduct.toLowerCase().includes(q) ||
        v.cweIds.some((c) => c.toLowerCase().includes(q))
    );
  }

  // Severity filter
  if (options.severity && options.severity !== 'ALL') {
    filtered = filtered.filter((v) => v.severity === options.severity);
  }

  // Source filter
  if (options.source && options.source !== 'ALL') {
    filtered = filtered.filter((v) => v.source === options.source);
  }

  // Vendor filter
  if (options.vendor && options.vendor !== 'ALL') {
    filtered = filtered.filter((v) => v.affectedVendor === options.vendor);
  }

  // Exploited only
  if (options.onlyExploited) {
    filtered = filtered.filter((v) => v.isKnownExploited);
  }

  // Ransomware only
  if (options.onlyRansomware) {
    filtered = filtered.filter((v) => v.hasRansomwareCampaign);
  }

  // Status filter
  if (options.status && options.status !== 'ALL') {
    filtered = filtered.filter((v) => v.status === options.status);
  }

  // Sorting
  const sortBy = options.sortBy || 'date_desc';
  filtered.sort((a, b) => {
    switch (sortBy) {
      case 'cvss_desc':
        return b.cvssScore - a.cvssScore;
      case 'cvss_asc':
        return a.cvssScore - b.cvssScore;
      case 'date_asc':
        return new Date(a.publishedDate).getTime() - new Date(b.publishedDate).getTime();
      case 'date_desc':
      default:
        return new Date(b.publishedDate).getTime() - new Date(a.publishedDate).getTime();
    }
  });

  return filtered;
}
