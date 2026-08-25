import { readFileSync } from "node:fs";

/**
 * @param {string} filePath
 * @returns {{pins: {name: string, version: string}[], skipped: string[]}}
 */

// shapely
// numpy>=1.24.0
// opencv-python==4.9.0.80
export async function parseRequirementsTxt(filePath) {
  const data = readFileSync(filePath, "utf-8");
  const lines = data.split("\n");
  const pins = [];
  const skipped = [];
  for (const line of lines) {
    if (line.startsWith("#") || line.trim() === "") {
      continue; // skip comments and empty lines
    }
    if (line.includes("==")) {
      const [name, version] = line.split("==");
      pins.push({ name: name.trim(), version: version.trim() });
    } else {
      skipped.push(line);
    }
  }
  return { pins, skipped };
}

export async function checkPyPIRegistry(packageName, version) {
  const url = version
    ? `https://pypi.org/pypi/${packageName}/${version}/json`
    : `https://pypi.org/pypi/${packageName}/json`;
  try {
    const response = await fetch(url);
    if (!response.ok) return null; // 404 = version/package not found
    return await response.json();
  } catch {
    return null;
  }
}

export async function buildPythonDependencyTree(pins, ecosystem = "PyPI") {
  const resolved = {};
  const visited = new Set();
  const queue = pins.map((pin) => ({
    name: pin.name,
    version: pin.version,
    parentName: null,
    direct: true,
  }));

  while (queue.length > 0) {
    const { name, version, parentName, direct } = queue.shift();
    const dedupeKey = name.toLowerCase().replace(/[-_.]+/g, "-"); // PyPI names are case-insensitive by convention

    if (visited.has(dedupeKey)) {
      const existing = resolved[dedupeKey];
      if (existing && parentName && !existing.parents.includes(parentName)) {
        existing.parents.push(parentName);
      }
      continue; // <- the missing fix: actually stop here, don't re-fetch
    }

    const data = await checkPyPIRegistry(name, version);
    if (!data || !data.info) {
      console.warn(
        `  [warn] could not resolve ${name}${version ? `@${version}` : ""} on PyPI` +
          (parentName ? ` (required by ${parentName})` : ""),
      );
      visited.add(dedupeKey);
      continue;
    }

    visited.add(dedupeKey);
    resolved[dedupeKey] = {
      name: data.info.name, // PyPI's own canonical casing, not whatever requires_dist happened to use
      version: data.info.version,
      ecosystem,
      direct,
      parents: parentName ? [parentName] : [],
    };

    const childNames = parseRequiresDist(data.info.requires_dist);
    for (const childName of childNames) {
      queue.push({
        name: childName,
        version: null,
        parentName: data.info.name, // also use canonical name here, so parent references stay consistent
        direct: false,
      });
    }
  }

  return resolved;
}
function parseRequiresDist(requiresDist) {
  const names = [];
  for (const raw of requiresDist || []) {
    if (raw.includes("extra ==")) continue;

    const stopIndex = raw.search(/[><=!~; ]/); // first version-operator char OR space
    const name = stopIndex === -1 ? raw : raw.slice(0, stopIndex);
    names.push(name.trim());
  }
  return names;
}
