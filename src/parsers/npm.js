import { readFileSync } from "node:fs";

export function readPackageFile(file) {
  const data = readFileSync(file, "utf-8");
  return JSON.parse(data);
}
export function extractDependencyNames(pkgObj, includeDev = true) {
  const names = Object.keys(pkgObj.dependencies || {});
  if (includeDev) {
    names.push(...Object.keys(pkgObj.devDependencies || {}));
  }
  return names;
}

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

function resolveChild(graph, childName, parentName) {
  const candidates = graph[childName] || [];
  const nested = candidates.find((c) => c.parent === parentName);
  const chosen = nested || candidates.find((c) => c.parent === null);
  return chosen;
}

// function traverseGraph(graph){
//   //to return
//   // {name, version, ecosystem, direct, parents}
//   // get all the top level packages/keys
//   const flattenedGraph = [];
//   const visited = new Set()
//   const topLevelPkgNames = Object.keys(graph)
//   const queue = topLevelPkgNames.map((key) => ({name:key, parentName: null, direct: true}))
//   while(queue.length){
//     let {name, parentName} = queue.shift();
//     const correctChild = resolveChild(graph, name, parentName);
//     const dependencies = graph[correctChild].dependencies
//     for (let dependent of dependencies){
//         flattenedGraph.push({name, dependent.version, ecosystem: "npm", direct, parentName})

//     }

//   }

// }
