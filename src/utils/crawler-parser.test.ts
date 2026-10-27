import test from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeSeverity,
  parseCvssVector,
  parseCisaKevFeed,
  parseGitHubAdvisoryFeed,
  parseNvdFeed,
  deduplicateVulnerabilities,
  computeVulnerabilityStats,
  filterAndSortVulnerabilities,
} from './crawler-parser';
import { Vulnerability } from '../types/vulnerability';

test('normalizeSeverity correctly identifies severity levels', () => {
  assert.equal(normalizeSeverity(9.8), 'CRITICAL');
  assert.equal(normalizeSeverity(7.5), 'HIGH');
  assert.equal(normalizeSeverity(5.4), 'MEDIUM');
  assert.equal(normalizeSeverity(2.1), 'LOW');
  assert.equal(normalizeSeverity(undefined, 'critical'), 'CRITICAL');
  assert.equal(normalizeSeverity(undefined, 'HIGH'), 'HIGH');
  assert.equal(normalizeSeverity(undefined, 'moderate'), 'UNKNOWN');
  assert.equal(normalizeSeverity(undefined, 'medium'), 'MEDIUM');
});

test('parseCvssVector correctly parses attack vector and parameters', () => {
  const v1 = parseCvssVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
  assert.equal(v1.attackVector, 'NETWORK');
  assert.equal(v1.attackComplexity, 'LOW');
  assert.equal(v1.privilegesRequired, 'NONE');
  assert.equal(v1.userInteraction, 'NONE');

  const v2 = parseCvssVector('CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:N/A:N');
  assert.equal(v2.attackVector, 'LOCAL');
  assert.equal(v2.attackComplexity, 'HIGH');
  assert.equal(v2.privilegesRequired, 'HIGH');
  assert.equal(v2.userInteraction, 'REQUIRED');

  const vEmpty = parseCvssVector(undefined);
  assert.equal(vEmpty.attackVector, 'UNKNOWN');
});

test('parseCisaKevFeed extracts vulnerabilities correctly with ransomware flag', () => {
  const rawCisa = {
    title: 'CISA Catalog of Known Exploited Vulnerabilities',
    count: 2,
    vulnerabilities: [
      {
        cveID: 'CVE-2024-38063',
        vendorProject: 'Microsoft',
        product: 'Windows',
        vulnerabilityName: 'Windows TCP/IP Remote Code Execution Vulnerability',
        dateAdded: '2024-08-20',
        shortDescription: 'Microsoft Windows TCP/IP contains a remote code execution vulnerability.',
        requiredAction: 'Apply updates per vendor instructions.',
        dueDate: '2024-09-10',
        knownRansomwareCampaignUse: 'Known',
        cwes: ['CWE-787'],
      },
      {
        cveID: 'CVE-2024-21762',
        vendorProject: 'Fortinet',
        product: 'FortiOS',
        vulnerabilityName: 'Fortinet FortiOS Out-of-Bound Write Vulnerability',
        dateAdded: '2024-02-09',
        shortDescription: 'A out-of-bounds write in Fortinet FortiOS may allow unauthenticated attacker to execute code.',
        requiredAction: 'Apply mitigations per vendor instructions.',
        dueDate: '2024-02-16',
        knownRansomwareCampaignUse: 'Unknown',
        cwes: 'CWE-787',
      },
    ],
  };

  const parsed = parseCisaKevFeed(rawCisa);
  assert.equal(parsed.length, 2);
  assert.equal(parsed[0].id, 'CVE-2024-38063');
  assert.equal(parsed[0].source, 'CISA_KEV');
  assert.equal(parsed[0].isKnownExploited, true);
  assert.equal(parsed[0].hasRansomwareCampaign, true);
  assert.equal(parsed[0].cweIds[0], 'CWE-787');
  assert.equal(parsed[1].hasRansomwareCampaign, false);
});

test('deduplicateVulnerabilities merges data without duplicates', () => {
  const item1: Vulnerability = {
    id: 'CVE-2024-38063',
    title: 'Title 1',
    description: 'Desc 1',
    source: 'NVD_NIST',
    sourceNameFa: 'NVD',
    sourceUrl: 'http://test.com',
    severity: 'HIGH',
    cvssScore: 8.5,
    cweIds: ['CWE-787'],
    affectedVendor: 'Microsoft',
    affectedProduct: 'Windows',
    affectedVersions: '10, 11',
    publishedDate: '2024-08-13T00:00:00Z',
    updatedDate: '2024-08-13T00:00:00Z',
    isKnownExploited: false,
    hasRansomwareCampaign: false,
    patchAvailable: true,
    references: [{ title: 'Ref 1', url: 'https://ref1.com' }],
    status: 'active',
  };

  const item2: Vulnerability = {
    id: 'CVE-2024-38063',
    title: 'Title 2 (CISA)',
    description: 'Desc 2',
    source: 'CISA_KEV',
    sourceNameFa: 'CISA KEV',
    sourceUrl: 'http://cisa.gov',
    severity: 'CRITICAL',
    cvssScore: 9.8,
    cweIds: ['CWE-787', 'CWE-119'],
    affectedVendor: 'Microsoft',
    affectedProduct: 'Windows TCP/IP',
    affectedVersions: 'All versions',
    publishedDate: '2024-08-20T00:00:00Z',
    updatedDate: '2024-08-20T00:00:00Z',
    isKnownExploited: true,
    hasRansomwareCampaign: true,
    patchAvailable: true,
    references: [{ title: 'Ref 2', url: 'https://ref2.com' }],
    status: 'active',
  };

  const deduplicated = deduplicateVulnerabilities([item1, item2]);
  assert.equal(deduplicated.length, 1);
  assert.equal(deduplicated[0].id, 'CVE-2024-38063');
  assert.equal(deduplicated[0].cvssScore, 9.8);
  assert.equal(deduplicated[0].severity, 'CRITICAL');
  assert.equal(deduplicated[0].isKnownExploited, true);
  assert.equal(deduplicated[0].hasRansomwareCampaign, true);
  assert.equal(deduplicated[0].cweIds.length, 2);
  assert.equal(deduplicated[0].references.length, 2);
});

test('computeVulnerabilityStats and filterAndSort work accurately', () => {
  const items: Vulnerability[] = [
    {
      id: 'CVE-2024-0001',
      title: 'Apache HTTP RCE',
      description: 'Severe RCE in Apache HTTP Server',
      source: 'CISA_KEV',
      sourceNameFa: 'CISA',
      sourceUrl: '',
      severity: 'CRITICAL',
      cvssScore: 9.8,
      cweIds: ['CWE-787'],
      affectedVendor: 'Apache',
      affectedProduct: 'HTTP Server',
      affectedVersions: '2.4',
      publishedDate: '2024-08-01T00:00:00Z',
      updatedDate: '2024-08-01T00:00:00Z',
      isKnownExploited: true,
      hasRansomwareCampaign: true,
      patchAvailable: true,
      references: [],
      status: 'active',
      attackVector: 'NETWORK',
    },
    {
      id: 'CVE-2024-0002',
      title: 'Microsoft Local Privilege Escalation',
      description: 'Elevation of privilege in Windows kernel',
      source: 'NVD_NIST',
      sourceNameFa: 'NVD',
      sourceUrl: '',
      severity: 'HIGH',
      cvssScore: 7.8,
      cweIds: ['CWE-269'],
      affectedVendor: 'Microsoft',
      affectedProduct: 'Windows',
      affectedVersions: '11',
      publishedDate: '2024-08-05T00:00:00Z',
      updatedDate: '2024-08-05T00:00:00Z',
      isKnownExploited: false,
      hasRansomwareCampaign: false,
      patchAvailable: true,
      references: [],
      status: 'watching',
      attackVector: 'LOCAL',
    },
  ];

  const stats = computeVulnerabilityStats(items, '2024-08-05T12:00:00Z');
  assert.equal(stats.total, 2);
  assert.equal(stats.critical, 1);
  assert.equal(stats.high, 1);
  assert.equal(stats.activelyExploited, 1);
  assert.equal(stats.ransomwareLinked, 1);
  assert.equal(stats.watching, 1);

  // Test filter
  const filteredSearch = filterAndSortVulnerabilities(items, { searchQuery: 'Apache' });
  assert.equal(filteredSearch.length, 1);
  assert.equal(filteredSearch[0].id, 'CVE-2024-0001');

  const filteredExploited = filterAndSortVulnerabilities(items, { onlyExploited: true });
  assert.equal(filteredExploited.length, 1);

  const sortedCvss = filterAndSortVulnerabilities(items, { sortBy: 'cvss_desc' });
  assert.equal(sortedCvss[0].id, 'CVE-2024-0001');
});
