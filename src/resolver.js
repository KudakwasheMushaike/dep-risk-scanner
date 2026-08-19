import { parsePackageLock } from "./parsers/npm.js";

/**
 * Given a specific package name and the parent requesting it, pick which
 * specific version-entry of that child applies - there could be multiple version
 * some not necessarily pulled in by that parent
 * optional/peer dependencies will return undefined here
 * @param {Object} graph
 * @param {string} childName
 * @param {string | null} parentName
 * @returns {{version: string, dev: boolean, parent: string | null, dependencies: string []} | undefined}
 */
function pickVersionForParent(graph, childName, parentName) {
  const candidates = graph[childName] || [];
  const nested = candidates.find((c) => c.parent === parentName);
  const chosen = nested || candidates.find((c) => c.parent === null);
  return chosen;
}

/**
 *  Walks the full dependency tree via BFS< starting from a projects
 * direct dependency names, and produces a flat map of every package used (direct
 * and transitive, with real resolved versions and who pulled each one in)
 * @param {string []} rootNames
 * @param {Object} graph
 * @param {string} [ecosystem= "npm"]
 * @returns {Object.<string, {name:string, version: string, ecosystem: string, direct: boolean, parents: string[]}>}
 * keyed by "name@version"
 */
export function buildDependencyTree(rootNames, graph, ecosystem = "npm") {
  const flattenedGraph = {};
  const visited = new Set();
  const queue = rootNames.map((name) => ({
    name,
    parentName: null,
    direct: true,
  }));

  while (queue.length > 0) {
    const { name, parentName, direct } = queue.shift();

    const entry = pickVersionForParent(graph, name, parentName);
    if (!entry) {
      console.warn(
        ` [warn] could not resolve dependency: ${name}` +
          (parentName ? `required by ${parentName}` : ""),
      );
      continue;
    }

    const key = `${name}@${entry.version}`;

    if (visited.has(key)) {
      const entryAlreadyInFlattenedGraph = flattenedGraph[key];
      if (
        parentName &&
        !entryAlreadyInFlattenedGraph.parents.includes(parentName)
      ) {
        entryAlreadyInFlattenedGraph.parents.push(parentName);
      }
      continue;
    }

    visited.add(key);

    flattenedGraph[key] = {
      name,
      version: entry.version,
      ecosystem,
      direct,
      parents: parentName ? [parentName] : [],
    };

    for (const childName of entry.dependencies) {
      queue.push({ name: childName, parentName: name, direct: false });
    }
  }

  return flattenedGraph;
}
