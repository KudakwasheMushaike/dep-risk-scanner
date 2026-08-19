// import {
//   readPackageFile,
//   extractDependencyNames,
//   parsePackageLock,
// } from "../src/parsers/npm.js";
import { readFileSync, writeFileSync } from "node:fs";

// const result = readPackageFile("./tests/sample-package.json");
// // console.log(extractDependencyNames(result));

// const graph = parsePackageLock("./tests/sample-lockfile.json");
// // console.log(graph);
// writeFileSync("./tests/graph-output.json", JSON.stringify(graph, null, 2));

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
} from "../src/vulnSources/osv.js";

const pkgObj = readPackageFile("./tests/sample-package.json");
const rootNames = extractDependencyNames(pkgObj);
const graph = parsePackageLock("./tests/sample-lockfile.json");
const flattenedGraph = buildDependencyTree(rootNames, graph);

// console.log("total resolved:", Object.keys(flattenedGraph).length);
// console.log(
//   "zod entries:",
//   Object.keys(result).filter((k) => k.startsWith("zod@")),
// );
// console.log(result);

const results = await queryOsvBatch(Object.values(flattenedGraph));
writeFileSync("./tests/results-output.json", JSON.stringify(results, null, 2));

// console.log(JSON.stringify(results, null, 2));

const finalizedList = await queryOsvBatch(Object.values(flattenedGraph));
const uniqueIds = uniqueVulnIDs(finalizedList);
console.log("unique advisory count:", uniqueIds.size);

const details = await fetchFullDetails(uniqueIds);
const firstId = Array.from(uniqueIds)[0];
console.log(JSON.stringify(details[firstId], null, 2));
