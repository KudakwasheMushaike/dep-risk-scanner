// scripts/manual-test-python.js
import { mkdirSync, writeFileSync } from "node:fs";
import {
  parseRequirementsTxt,
  buildPythonDependencyTree,
} from "../src/parsers/python.js";

const PYTHON_FIXTURE = "./tests/fixtures/python/requirements.txt";
const RESOLVED_OUTPUT = "./tests/output/python-resolved.json";

/**
 * Runs the manual Python resolver smoke test and writes the resolved tree fixture output.
 *
 * @returns {Promise<void>}
 */
async function main() {
  const { pins, skipped } = await parseRequirementsTxt(PYTHON_FIXTURE);
  console.log("pins:", pins);
  console.log("skipped:", skipped);

  const resolved = await buildPythonDependencyTree(pins);

  const resolvedList = Object.values(resolved);
  console.log(`\nResolved ${resolvedList.length} package(s):\n`);
  for (const dep of resolvedList) {
    console.log(
      `${dep.direct ? "[direct]    " : "[transitive]"} ${dep.name}@${dep.version}` +
        (dep.parents.length ? ` (via ${dep.parents.join(", ")})` : ""),
    );
  }

  mkdirSync("./tests/output", { recursive: true });
  writeFileSync(RESOLVED_OUTPUT, JSON.stringify(resolved, null, 2));
  console.log(`\nWrote full resolved tree to ${RESOLVED_OUTPUT}`);
}

main();
