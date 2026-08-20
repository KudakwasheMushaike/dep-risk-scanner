// src/mergeVulnSources.js

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
        existingIds.add(info.id);
        if (info.cve) existingIds.add(info.cve);
      }
    }
  }

  return Object.values(merged);
}
