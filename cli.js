#!/usr/bin/env node
try {
  process.loadEnvFile(".env");
} catch {
  // no .env file present — fine, just means no GITHUB_TOKEN, GHSA falls back to unauthenticated
}

import {
  readPackageFile,
  extractDependencyNames,
  parsePackageLock,
} from "./src/parsers/npm.js";
import { buildDependencyTree } from "./src/resolver.js";
import {
  queryOsvBatch,
  uniqueVulnIDs,
  fetchFullDetails,
  buildVulnerabilityReport,
} from "./src/vulnSources/osv.js";
import { queryGhsaBatch, extractGhsaVulnInfo } from "./src/vulnSources/ghsa.js";
import { mergeVulnSources } from "./src/merge.js";
import {
  buildSummary,
  printConsoleReport,
  writeJsonReport,
} from "./src/report.js";
import path from "node:path";

function parseArgs(argv) {
  const args = { manifest: null, jsonOut: null };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--json-out") {
      args.jsonOut = argv[++i];
    } else if (!args.manifest) {
      args.manifest = argv[i];
    }
  }
  return args;
}

async function main() {
  const { manifest, jsonOut } = parseArgs(process.argv.slice(2));

  if (!manifest) {
    console.error(
      "Usage: ./cli.js <package.json|requirements.txt> [--json-out report.json]",
    );
    process.exit(1);
  }

  const manifestName = path.basename(manifest);
  const manifestDir = path.dirname(manifest);

  if (manifestName !== "package.json") {
    console.error(
      `Only package.json is currently supported (got: ${manifestName}). Python support coming next.`,
    );
    process.exit(1);
  }

  console.log(`Resolving dependencies for ${manifest}...`);
  const pkgObj = readPackageFile(manifest);
  const rootNames = extractDependencyNames(pkgObj);
  const lockfilePath = path.join(manifestDir, "package-lock.json");
  const graph = parsePackageLock(lockfilePath);
  const flattenedGraph = buildDependencyTree(rootNames, graph);
  console.log(`  Resolved ${Object.keys(flattenedGraph).length} packages.`);

  console.log("Querying OSV.dev...");
  const finalizedList = await queryOsvBatch(Object.values(flattenedGraph));
  const uniqueIds = uniqueVulnIDs(finalizedList);
  const details = await fetchFullDetails(uniqueIds);
  const osvReport = buildVulnerabilityReport(finalizedList, details);

  console.log("Querying GitHub Security Advisories...");
  const ghsaResults = await queryGhsaBatch(Object.values(flattenedGraph));
  const finalReport = mergeVulnSources(
    osvReport,
    ghsaResults,
    extractGhsaVulnInfo,
  );

  const summary = buildSummary(flattenedGraph, finalReport);
  printConsoleReport(finalReport, summary);

  if (jsonOut) {
    writeJsonReport(finalReport, summary, jsonOut);
    console.log(`\nJSON report written to ${jsonOut}`);
  }
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
