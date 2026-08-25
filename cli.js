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
import {
  parseRequirementsTxt,
  buildPythonDependencyTree,
} from "./src/parsers/python.js";
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

async function resolveNpm(manifestPath, manifestDir) {
  const pkgObj = readPackageFile(manifestPath);
  const rootNames = extractDependencyNames(pkgObj);
  const lockfilePath = path.join(manifestDir, "package-lock.json");
  const graph = parsePackageLock(lockfilePath);
  const flattenedGraph = buildDependencyTree(rootNames, graph);
  return { flattenedGraph, skipped: [] };
}

async function resolvePython(manifestPath) {
  const { pins, skipped } = await parseRequirementsTxt(manifestPath);
  if (skipped.length > 0) {
    console.log(
      `  [warn] ${skipped.length} requirement(s) could not be resolved to an exact version, skipping: ${skipped.join(", ")}`,
    );
  }
  const flattenedGraph = await buildPythonDependencyTree(pins);
  return { flattenedGraph, skipped };
}

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

  console.log(`Resolving dependencies for ${manifest}...`);

  let flattenedGraph;
  let skipped;

  if (manifestName === "package.json") {
    ({ flattenedGraph, skipped } = await resolveNpm(manifest, manifestDir));
  } else if (manifestName === "requirements.txt") {
    ({ flattenedGraph, skipped } = await resolvePython(manifest));
  } else {
    console.error(
      `Unrecognized manifest '${manifestName}'. Expected package.json or requirements.txt.`,
    );
    process.exit(1);
  }

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

  const summary = buildSummary(flattenedGraph, finalReport, skipped);
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
