import { writeFileSync } from "node:fs";

const SEVERITY_ORDER = {
  CRITICAL: 0,
  HIGH: 1,
  MODERATE: 2,
  LOW: 3,
  UNKNOWN: 4,
};
const COLOR = {
  CRITICAL: "\x1b[1;31m",
  HIGH: "\x1b[31m",
  MODERATE: "\x1b[33m",
  LOW: "\x1b[36m",
  UNKNOWN: "\x1b[90m",
};
const RESET = "\x1b[0m";

/**
 * Computes the summary stats:
 * total dependencies, vulnerable count/percentage, plus a severity
 * breakdown (counted per-vulnerability, not per-package, since one
 * package can carry multiple advisories of different severities).
 *
 * @param {Object.<string, {direct: boolean}>} flattenedGraph - Flattened dependency map keyed by package identity.
 * @param {{vulnerabilities: {severity: string}[]}[]} finalReport - Merged vulnerable package report.
 * @param {string[]} [skipped=[]] - Requirements that could not be resolved and scanned.
 * @returns {{totalDependencies: number, directDependencies: number, transitiveDependencies: number, vulnerablePackages: number, vulnerablePercentage: number, bySeverity: Object.<string, number>, skipped: string[]}}
 */
export function buildSummary(flattenedGraph, finalReport, skipped = []) {
  const allDeps = Object.values(flattenedGraph);
  const total = allDeps.length;
  const direct = allDeps.filter((d) => d.direct).length;

  const bySeverity = { CRITICAL: 0, HIGH: 0, MODERATE: 0, LOW: 0, UNKNOWN: 0 };
  for (const pkg of finalReport) {
    for (const vuln of pkg.vulnerabilities) {
      bySeverity[vuln.severity] = (bySeverity[vuln.severity] || 0) + 1;
    }
  }

  return {
    totalDependencies: total,
    directDependencies: direct,
    transitiveDependencies: total - direct,
    vulnerablePackages: finalReport.length,
    vulnerablePercentage: total
      ? Number(((finalReport.length / total) * 100).toFixed(1))
      : 0,
    bySeverity,
    skipped,
  };
}

/**
 * Orders vulnerable package entries by their worst vulnerability severity.
 *
 * @param {{vulnerabilities: {severity: string}[]}[]} finalReport - Vulnerable package report entries.
 * @returns {{vulnerabilities: {severity: string}[]}[]} sorted report entries.
 */
function sortBySeverity(finalReport) {
  const worstSeverity = (pkg) =>
    Math.min(
      ...pkg.vulnerabilities.map((v) => SEVERITY_ORDER[v.severity] ?? 4),
    );
  return [...finalReport].sort((a, b) => worstSeverity(a) - worstSeverity(b));
}

/**
 * Prints a human-readable dependency risk report to stdout.
 *
 * @param {{nameAtVersion: string, recommendedUpgrade?: string|null, vulnerabilities: Object[]}[]} finalReport - Merged vulnerable package report.
 * @param {Object} summary - Summary produced by buildSummary.
 * @param {boolean} [useColor=true] - Whether to color severity labels with ANSI codes.
 * @returns {void}
 */
export function printConsoleReport(finalReport, summary, useColor = true) {
  const c = (severity, text) =>
    useColor ? `${COLOR[severity] || ""}${text}${RESET}` : text;

  console.log("\n=== Dependency Risk Scan ===");
  console.log(
    `Total dependencies:      ${summary.totalDependencies} ` +
      `(${summary.directDependencies} direct, ${summary.transitiveDependencies} transitive)`,
  );
  console.log(
    `Vulnerable dependencies: ${summary.vulnerablePackages} (${summary.vulnerablePercentage}%)`,
  );

  const severityLine = Object.entries(summary.bySeverity)
    .filter(([, count]) => count > 0)
    .map(([sev, count]) => `${c(sev, sev)}: ${count}`)
    .join("  ");
  if (severityLine) console.log(`By severity:              ${severityLine}`);

  if (finalReport.length === 0) {
    console.log("\nNo known vulnerabilities found. \u2713");
    return;
  }

  if (summary.skipped && summary.skipped.length > 0) {
    console.log(
      `\nSkipped ${summary.skipped.length} requirement(s) (unresolvable, not scanned):`,
    );
    for (const line of summary.skipped) {
      console.log(`  - ${line}`);
    }
  }

  console.log("\n--- Vulnerable Packages ---");
  for (const pkg of sortBySeverity(finalReport)) {
    const worst = pkg.vulnerabilities
      .map((v) => v.severity)
      .sort((a, b) => SEVERITY_ORDER[a] - SEVERITY_ORDER[b])[0];

    console.log(`\n${c(worst, worst)} ${pkg.nameAtVersion}`);
    if (pkg.recommendedUpgrade) {
      console.log(
        `  Recommended upgrade: ${pkg.recommendedUpgrade} (resolves all ${pkg.vulnerabilities.length} below)`,
      );
    }
    for (const v of pkg.vulnerabilities) {
      console.log(
        `  [${c(v.severity, v.severity)}] ${v.id}${v.cve ? ` (${v.cve})` : ""}`,
      );
      console.log(`    ${v.summary}`);
      console.log(
        `    fix: ${v.fixedVersion || "no fix published yet"}  |  ${v.advisoryUrl}`,
      );
    }
  }
}

/**
 * Writes the dependency risk report and summary to a JSON file.
 *
 * @param {Object[]} finalReport - Merged vulnerable package report.
 * @param {Object} summary - Summary produced by buildSummary.
 * @param {string} outputPath - Destination path for the JSON report.
 * @returns {void}
 */
export function writeJsonReport(finalReport, summary, outputPath) {
  const json = {
    summary,
    vulnerablePackages: sortBySeverity(finalReport),
  };
  writeFileSync(outputPath, JSON.stringify(json, null, 2));
}
