import { readFileSync } from "node:fs";

/**
 * Reads and parses a package.json file.
 *
 * @param {string} file - Path to package.json.
 * @returns {Object} parsed package manifest.
 */
export function readPackageFile(file) {
  const data = readFileSync(file, "utf-8");
  return JSON.parse(data);
}

/**
 * Extracts direct dependency names from package.json dependencies and, optionally, devDependencies.
 *
 * @param {Object} pkgObj - Parsed package manifest.
 * @param {boolean} [includeDev=true] - Whether to include devDependencies.
 * @returns {string[]} dependency package names.
 */
export function extractDependencyNames(pkgObj, includeDev = true) {
  const names = Object.keys(pkgObj.dependencies || {});
  if (includeDev) {
    names.push(...Object.keys(pkgObj.devDependencies || {}));
  }
  return names;
}

/**
 * Parses package-lock.json into a package graph grouped by dependency name.
 *
 * @param {string} file - Path to package-lock.json.
 * @returns {Object.<string, {version: string, dev: boolean, parent: string|null, dependencies: string[]}[]>}
 */
export function parsePackageLock(file) {
  const graph = {};
  const data = readFileSync(file, "utf-8");
  const pkgLock = JSON.parse(data);
  const packageObjects = pkgLock.packages || {};
  const packageObjectKeys = Object.keys(packageObjects);
  for (const pkgObjkey of packageObjectKeys) {
    if (pkgObjkey == "") {
      // root
      continue;
    }
    const pkg = packageObjects[pkgObjkey];
    const parts = pkgObjkey.split("node_modules/");
    const name = parts.pop(); // keep just the bare name
    const parent = parts.length > 1 ? parts.pop().replace(/\/$/, "") : null;
    const dependencies = Object.keys(pkg.dependencies || {});
    if (graph[name] == undefined) {
      graph[name] = [];
    }
    graph[name].push({
      version: pkg.version,
      dev: pkg.dev || false,
      parent,
      dependencies,
    });
  }
  return graph;
}

/**
 * Resolves which installed child package entry applies for a requesting parent.
 *
 * @param {Object.<string, {version: string, parent: string|null, dependencies: string[]}[]>} graph - Parsed npm lockfile graph.
 * @param {string} childName - Dependency name being resolved.
 * @param {string|null} parentName - Parent package requesting the dependency.
 * @returns {{version: string, parent: string|null, dependencies: string[]}|undefined}
 */
function resolveChild(graph, childName, parentName) {
  const candidates = graph[childName] || [];
  const nested = candidates.find((c) => c.parent === parentName);
  const chosen = nested || candidates.find((c) => c.parent === null);
  return chosen;
}
