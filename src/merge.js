import semver from "semver";

/**
 * Combines OSV and GHSA vulnerability reports, deduplicating advisories by ID/CVE
 * and computing one recommended upgrade target per package.
 *
 * @param {{nameAtVersion: string, vulnerabilities: Object[]}[]} osvReport - Normalized OSV report entries.
 * @param {Object.<string, Object[]>} ghsaResults - Raw GHSA advisories keyed by "name@version".
 * @param {(rawAdvisory: Object) => Object} extractGhsaVulnInfo - Normalizes one GHSA advisory.
 * @returns {{nameAtVersion: string, vulnerabilities: Object[], recommendedUpgrade: string|null}[]}
 */
export function mergeVulnSources(osvReport, ghsaResults, extractGhsaVulnInfo) {
  const merged = {};
  for (const entry of osvReport) {
    merged[entry.nameAtVersion] = {
      nameAtVersion: entry.nameAtVersion,
      vulnerabilities: [...entry.vulnerabilities],
    };
  }

  for (const [nameAtVersion, rawAdvisories] of Object.entries(ghsaResults)) {
    if (!merged[nameAtVersion]) {
      merged[nameAtVersion] = { nameAtVersion, vulnerabilities: [] };
    }

    const existingIds = new Set(
      merged[nameAtVersion].vulnerabilities.flatMap((v) =>
        [v.id, v.cve].filter(Boolean),
      ),
    );

    for (const rawAdvisory of rawAdvisories) {
      const info = extractGhsaVulnInfo(rawAdvisory);
      const alreadyHave =
        existingIds.has(info.id) || (info.cve && existingIds.has(info.cve));
      if (!alreadyHave) {
        merged[nameAtVersion].vulnerabilities.push(info);
      }
    }
  }

  // roll up each package's vulnerabilities into one recommended upgrade
  // target — the highest fixed version across all of them. A later
  // patch almost always still contains earlier security fixes, so one
  // upgrade typically resolves everything rather than needing separate
  // upgrades per vulnerability.
  for (const entry of Object.values(merged)) {
    const fixedVersions = entry.vulnerabilities
      .map((v) => v.fixedVersion)
      .filter(Boolean);
    entry.recommendedUpgrade = fixedVersions.length
      ? fixedVersions.sort(semver.rcompare)[0]
      : null;
  }

  return Object.values(merged);
}
