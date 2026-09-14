const { SEVERITY_LEVELS } = require('../constants');

function createFinding({
  name,
  desc,
  severity,
  cwe = '',
  path = '/',
  parameter = '',
  impact = '',
  fix = '',
  scanner = '',
  category = '',
  subCategory = '',
  cvssScore = null,
  evidence = '',
  references = []
}) {
  const tone = severity.toLowerCase();
  return {
    name,
    desc,
    severity,
    tone: ['critical', 'high', 'medium', 'low'].includes(tone) ? tone : 'medium',
    cwe,
    path,
    parameter,
    impact,
    fix,
    scanner,
    category,
    subCategory,
    cvssScore,
    evidence,
    references
  };
}

function createResult(scanner, findings = [], metadata = {}, success = true) {
  return {
    scanner,
    success,
    findings,
    metadata
  };
}

function countSeverities(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };

  findings.forEach((finding) => {
    const key = finding.severity?.toLowerCase();
    if (counts[key] !== undefined) {
      counts[key] += 1;
    }
  });

  return counts;
}

function computeRiskScore(counts) {
  const score =
    counts.critical * 25 +
    counts.high * 15 +
    counts.medium * 7 +
    counts.low * 2;

  return Math.min(100, score);
}

function computeDomainScore(counts) {
  const penalty =
    counts.critical * 18 +
    counts.high * 10 +
    counts.medium * 5 +
    counts.low * 1;

  return Math.max(30, 100 - penalty);
}

function resolveScoreLabel(score) {
  if (score >= 80) return { label: 'Excellent', tone: 'excellent' };
  if (score >= 60) return { label: 'Good', tone: 'good' };
  return { label: 'Needs Attention', tone: 'attention' };
}

function withTimeout(promise, ms, label) {
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
    })
  ]);
}

module.exports = {
  SEVERITY_LEVELS,
  createFinding,
  createResult,
  countSeverities,
  computeRiskScore,
  computeDomainScore,
  resolveScoreLabel,
  withTimeout
};