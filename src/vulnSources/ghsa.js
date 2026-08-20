const ECOSYSTEM_MAP = { npm: "npm", PyPI: "pip" };

/**
 *
 * @param {*} dep
 * @returns
 */
async function queryGhsaForDependency(dep) {
  const ecosystem = ECOSYSTEM_MAP[dep.ecosystem];
  if (!ecosystem) return [];

  const params = new URLSearchParams({
    ecosystem,
    affects: `${dep.name}@${dep.version}`,
    per_page: "100",
  });

  const headers = { Accept: "application/vnd.github+json" };
  if (process.env.GITHUB_TOKEN) {
    headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  }

  try {
    const response = await fetch(
      `https://api.github.com/advisories?${params}`,
      { headers },
    );

    if (response.status === 403 || response.status === 429) {
      console.warn(`  [warn] GHSA rate-limited on ${dep.name}`);
      return [];
    }
    if (!response.ok) {
      console.warn(
        `  [warn] GHSA query failed for ${dep.name}: ${response.status}`,
      );
      return [];
    }

    const advisories = await response.json(); // now inside the try, covers malformed responses too
    return advisories.filter((a) => !a.withdrawn_at);
  } catch (error) {
    console.warn(
      `  [warn] GHSA request failed for ${dep.name}: ${error.message}`,
    );
    return [];
  }
}

export async function queryGhsaBatch(dependencies) {
  const fetches = dependencies.map(async (dep) => {
    const advisories = await queryGhsaForDependency(dep);
    return [`${dep.name}@${dep.version}`, advisories];
  });

  const results = await Promise.all(fetches);

  const byPackage = {};
  for (const [key, advisories] of results) {
    if (advisories.length > 0) {
      byPackage[key] = advisories;
    }
  }
  return byPackage;
}

export function extractGhsaVulnInfo(rawAdvisory) {
  let fixedVersion = null;
  for (const vuln of rawAdvisory.vulnerabilities || []) {
    const patched = vuln.first_patched_version?.identifier;
    if (patched) fixedVersion = patched;
  }

  return {
    id: rawAdvisory.ghsa_id,
    summary: rawAdvisory.summary,
    severity: (rawAdvisory.severity || "UNKNOWN").toUpperCase(),
    cve: rawAdvisory.cve_id || null,
    advisoryUrl: rawAdvisory.html_url,
    fixedVersion,
  };
}
