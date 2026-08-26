import {
  readPackageFile,
  extractDependencyNames,
  parsePackageLock,
} from "../src/parsers/npm.js";
import { buildDependencyTree } from "../src/resolver.js";
import {
  queryOsvBatch,
  uniqueVulnIDs,
  fetchFullDetails,
  buildVulnerabilityReport,
} from "../src/vulnSources/osv.js";
import {
  queryGhsaBatch,
  extractGhsaVulnInfo,
} from "../src/vulnSources/ghsa.js";
import { mergeVulnSources } from "../src/merge.js";

const NPM_FIXTURE_DIR = "./tests/fixtures/npm";

// --- Step 1: parse manifests ---
const pkgObj = readPackageFile(`${NPM_FIXTURE_DIR}/package.json`);
const rootNames = extractDependencyNames(pkgObj);
const graph = parsePackageLock(`${NPM_FIXTURE_DIR}/package-lock.json`);
console.log("direct dependency names:", rootNames.length);

// --- Step 2: resolve full dependency tree ---
const flattenedGraph = buildDependencyTree(rootNames, graph);
console.log("total resolved packages:", Object.keys(flattenedGraph).length);

// --- Step 3: check against OSV ---
const finalizedList = await queryOsvBatch(Object.values(flattenedGraph));
console.log("vulnerable packages found:", finalizedList.length);

// --- Step 4: dedupe + fetch full advisory details ---
const uniqueIds = uniqueVulnIDs(finalizedList);
console.log("unique advisories:", uniqueIds.size);

const details = await fetchFullDetails(uniqueIds);

// --- Step 5: build the final clean report data ---
const report = buildVulnerabilityReport(finalizedList, details);

console.log("\n=== SAMPLE REPORT ENTRY ===");
console.log(JSON.stringify(report[0], null, 2));

console.log("\n=== SUMMARY ===");
console.log(`${Object.keys(flattenedGraph).length} total dependencies`);
console.log(`${report.length} vulnerable packages`);
console.log(`${uniqueIds.size} unique advisories`);

const ghsaResults = await queryGhsaBatch(Object.values(flattenedGraph));
const finalReport = mergeVulnSources(report, ghsaResults, extractGhsaVulnInfo);

console.log("packages in final merged report:", finalReport.length);
console.log(JSON.stringify(finalReport, null, 2));

const osvNames = new Set(report.map((r) => r.nameAtVersion));
const extra = finalReport.filter((r) => !osvNames.has(r.nameAtVersion));
console.log("Package(s) GHSA found that OSV missed:");
console.log(JSON.stringify(extra, null, 2));
