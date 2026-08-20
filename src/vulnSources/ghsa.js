const ECOSYSTEM_MAP = { npm: "npm", PyPI: "pip" };
const GHSA_CONCURRENCY = 10;

class GhsaRateLimitError extends Error {
  constructor() {
    super("GHSA rate-limited");
  }
}

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

  let response;
  try {
    response = await fetch(`https://api.github.com/advisories?${params}`, {
      headers,
    });
  } catch (error) {
    console.warn(
      `  [warn] GHSA query failed for ${dep.name}: ${error.message}`,
    );
    return [];
  }

  if (response.status === 403 || response.status === 429) {
    throw new GhsaRateLimitError();
  }
  if (!response.ok) {
    console.warn(
      `  [warn] GHSA query failed for ${dep.name}: ${response.status}`,
    );
    return [];
  }

  const advisories = await response.json();
  return advisories.filter((a) => !a.withdrawn_at); // drop advisories GitHub has since withdrawn
}

/**
 *
 * @param {*} dependencies
 * @returns
 */
export async function queryGhsaBatch(dependencies) {
  const results = [];
  for (let i = 0; i < dependencies.length; i += GHSA_CONCURRENCY) {
    const chunk = dependencies.slice(i, i + GHSA_CONCURRENCY);
    const fetches = chunk.map(async (dep) => {
      try {
        const advisories = await queryGhsaForDependency(dep);
        return [`${dep.name}@${dep.version}`, advisories, false];
      } catch (error) {
        if (error instanceof GhsaRateLimitError) {
          return [`${dep.name}@${dep.version}`, [], true];
        }
        throw error;
      }
    });
    const chunkResults = await Promise.all(fetches);
    results.push(...chunkResults);

    if (chunkResults.some(([, , rateLimited]) => rateLimited)) {
      console.warn(
        "  [warn] GHSA rate-limited; set GITHUB_TOKEN to scan more packages",
      );
      break;
    }
  }

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
