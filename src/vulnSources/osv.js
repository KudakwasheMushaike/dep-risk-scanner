import semver from "semver";

/**
 *
 * @param {{name: string, version: string, ecosystem: string, direct: boolean, parents: string[]}[]} dependencies
 */
export async function queryOsvBatch(dependencies) {
  const body = {
    queries: dependencies.map((dep) => ({
      package: { name: dep.name, ecosystem: dep.ecosystem },
      version: dep.version,
    })),
  };

  const response = await fetch("https://api.osv.dev/v1/querybatch", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  const data = await response.json();
  const vulnResults = data.results;
  const finalizedList = [];
  for (let i = 0; i < vulnResults.length; i++) {
    let dep = dependencies[i];
    if (vulnResults[i].vulns) {
      finalizedList.push({
        [`${dep.name}@${dep.version}`]: vulnResults[i].vulns,
      });
    }
  }
  return finalizedList;
}

/**
 * Collects the unique set of vulnerability IDs referenced across all
 * entries in finalizedList (since the same advisory often affects
 * multiple packages
 * @param {Object[]} finalizedList - array of single-key objects: { "name@version": [{id, modified}, ...] }
 * @returns {Set<string>}
 */
export function uniqueVulnIDs(finalizedList) {
  const uniqueIds = new Set();
  for (const packageVulnEntry of finalizedList) {
    const vulnList = Object.values(packageVulnEntry)[0];
    for (const vuln of vulnList) {
      uniqueIds.add(vuln.id);
    }
  }
  return uniqueIds;
}

/**
 * Fetches full advisory details (summary, severity, fixed version, etc.)
 * for every ID in parallel, since each fetch is independent of the others.
 *
 * Each fetch retries up to 3 times on failure (network error, timeout,
 * non-2xx), since OSV lookups have been observed to fail intermittently
 * (e.g. transient DNS resolution issues) rather than consistently.
 *
 * @param {Set<string>} uniqueIds
 * @returns {Promise<Object>} map of { id: fullAdvisoryDetails }
 */
export async function fetchFullDetails(uniqueIds) {
  const ids = Array.from(uniqueIds);
  const maxRetries = 3;

  async function fetchWithRetry(id) {
    let lastError;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        const response = await fetch(`https://api.osv.dev/v1/vulns/${id}`);

        if (!response.ok) {
          throw new Error(`OSV returned ${response.status} for ${id}`);
        }

        return [id, await response.json()];
      } catch (err) {
        lastError = err;
        if (attempt < maxRetries) {
          console.warn(
            `Retrying ${id} (attempt ${attempt + 1}/${maxRetries})...`,
          );
        }
      }
    }

    throw lastError; // all retries exhausted — let it propagate and fail the batch
  }

  const fetches = ids.map(fetchWithRetry);
  const results = await Promise.all(fetches);

  const detailsById = {};
  for (const [id, details] of results) {
    detailsById[id] = details;
  }
  return detailsById;
}

/**
 * Finds the highest fixed version for a given package from an OSV advisory record.
 * Searches through affected package entries, extracts all fixed versions, and returns
 * the highest one according to semantic versioning.
 *
 * @param {Object[]} affected - array of affected entries from OSV advisory
 * @param {string} packageName - the package name to find a fix for
 * @returns {string|null} the highest fixed version, or null if no fix found
 */
function findFixedVersion(affected, packageName) {
  const fixedVersions = [];

  const matchingEntries = affected.filter(
    (a) => a.package.name === packageName,
  );
  for (const entry of matchingEntries) {
    for (const range of entry.ranges) {
      for (const event of range.events) {
        if (event.fixed) {
          fixedVersions.push(event.fixed);
        }
      }
    }
  }

  if (fixedVersions.length === 0) return null;

  // sort descending by semver, return the highest
  fixedVersions.sort(semver.rcompare);
  return fixedVersions[0];
}
/**
 * Splits a "name@version" string into separate name and version components.
 * Handles scoped packages (e.g. "@scope/package@1.0.0").
 *
 * @param {string} nameAtVersion - string in format "name@version" or "@scope/name@version"
 * @returns {{name: string, version: string}}
 */
function splitNameVersion(nameAtVersion) {
  const parts = nameAtVersion.split("@");
  const version = parts.pop();
  const name = parts.join("@");
  return { name, version };
}

/**
 * Builds a vulnerability report by combining package vulnerability references with
 * full advisory details, extracting relevant fields for each vulnerability.
 *
 * @param {Object[]} finalizedList - array of single-key objects from queryOsvBatch
 * @param {Object} details - map of advisory IDs to full advisory details
 * @returns {Array<{nameAtVersion: string, vulnerabilities: Array}>} vulnerability report
 */
export function buildVulnerabilityReport(finalizedList, details) {
  const report = [];

  for (const packageVulnEntry of finalizedList) {
    const [nameAtVersion, vulnRefs] = Object.entries(packageVulnEntry)[0];
    const { name } = splitNameVersion(nameAtVersion);

    const vulnDetails = vulnRefs.map((ref) => {
      const rawAdvisory = details[ref.id];
      return extractVulnInfo(rawAdvisory, name);
    });

    report.push({ nameAtVersion, vulnerabilities: vulnDetails });
  }

  return report;
}

/**
 * Extracts the fields we need from a raw OSV advisory record, scoped
 * to one specific package name (since one advisory can cover multiple
 * packages, each with its own fix version).
 *
 * @param {Object} rawAdvisory - one full record from fetchFullDetails
 * @param {string} packageName - the package we're building a report entry for
 * @returns {{id: string, summary: string, severity: string, cve: string|null, advisoryUrl: string, fixedVersion: string|null}}
 */
function extractVulnInfo(rawAdvisory, packageName) {
  const severity = rawAdvisory.database_specific?.severity || "UNKNOWN";
  const cve = rawAdvisory.aliases?.[0] || null;
  const advisoryUrl = `https://osv.dev/vulnerability/${rawAdvisory.id}`;
  const fixedVersion = findFixedVersion(rawAdvisory.affected, packageName);

  return {
    id: rawAdvisory.id,
    summary: rawAdvisory.summary,
    severity,
    cve,
    advisoryUrl,
    fixedVersion,
  };
}
