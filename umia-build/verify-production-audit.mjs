import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const [sourceDir, reviewedLockPath, expectedLockSha256] = process.argv.slice(2);
if (!sourceDir || !reviewedLockPath || !/^[a-f0-9]{64}$/.test(expectedLockSha256 ?? "")) {
  throw new Error(
    "Usage: verify-production-audit.mjs SOURCE_DIR REVIEWED_LOCK_PATH EXPECTED_LOCK_SHA256",
  );
}

const lockSha256 = createHash("sha256").update(readFileSync(reviewedLockPath)).digest("hex");
if (lockSha256 !== expectedLockSha256) {
  throw new Error("Source lockfile digest differs from the reviewed dependency patch");
}

const cryptoPackage = JSON.parse(
  readFileSync(join(sourceDir, "node_modules/@reclaimprotocol/zk-symmetric-crypto/package.json")),
);
const stwoWasm = readFileSync(
  join(sourceDir, "node_modules/@reclaimprotocol/zk-symmetric-crypto/lib/stwo/s2circuits_bg.wasm"),
);
if (
  cryptoPackage.version !== "5.1.7" ||
  createHash("sha256").update(stwoWasm).digest("hex") !==
    "8c4baf48a68956a87ccd6e7f737cbf549a2cdc722b80776068d9ee33f9347df1"
) {
  throw new Error("Production attestor does not contain the reviewed Stwo verifier WASM");
}

function runJson(args) {
  const result = spawnSync("npm", args, {
    cwd: sourceDir,
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
  });
  if (result.error || ![0, 1].includes(result.status)) {
    throw new Error(`npm ${args[0]} failed to execute`);
  }
  let data;
  try {
    data = JSON.parse(result.stdout);
  } catch {
    throw new Error(`npm ${args[0]} did not return JSON`);
  }
  if (data.error) throw new Error(`npm ${args[0]} returned an audit/tree error`);
  return { status: result.status, data };
}

const tree = runJson(["ls", "--omit=dev", "--all", "--json"]);
if (tree.status !== 0 || tree.data.problems?.length) {
  throw new Error("Production dependency tree contains installation problems");
}

const audit = runJson(["audit", "--omit=dev", "--json"]);
const counts = audit.data.metadata?.vulnerabilities;
const vulnerabilities = audit.data.vulnerabilities;
if (!counts || !vulnerabilities || typeof vulnerabilities !== "object") {
  throw new Error("npm audit returned no vulnerability inventory");
}
if (counts.total !== 0 || Object.keys(vulnerabilities).length !== 0 || audit.status !== 0) {
  throw new Error("Production dependency tree retains an npm audit finding");
}

console.log(
  JSON.stringify({
    packageLockSha256: lockSha256,
    productionFindings: counts,
    productionTreeProblems: 0,
  }),
);
