// Copyright (c) Microsoft Corporation.
// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.
//
// Packs dist/src/*.js and app.json into dist/bundle.json (the payload of
// PUT /app/userDefinedEndpoints on ACL, or set_js_app on CCF).
//
// bundle_digest = "sha256:" + hex(SHA-256(JCS({metadata, modules}))) where
// `modules` excludes the generated build_info.js module (which carries the
// digest itself) and is sorted by name. `depa dc audit` recomputes it from the
// bundle served by GET /app/userDefinedEndpoints.

import { createHash } from "crypto";
import { readdirSync, readFileSync, statSync, writeFileSync } from "fs";
import { join, posix, relative, sep } from "path";

const distDir = process.argv[2];
if (!distDir) throw new Error("usage: node build_bundle.js <distDir>");
const srcDir = join(distDir, "src");
const pkg = JSON.parse(readFileSync("package.json", "utf-8"));
const metadata = JSON.parse(readFileSync("app.json", "utf-8"));

function listFiles(dir) {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? listFiles(p) : [p];
  });
}

// JCS for JSON values made of objects, arrays, strings, booleans and integers.
function jcs(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + jcs(v[k])).join(",") + "}";
}

const modules = listFiles(srcDir)
  .map((p) => ({ name: relative(srcDir, p).split(sep).join(posix.sep), module: readFileSync(p, "utf-8") }))
  .filter((m) => m.name !== "build_info.js")
  .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

const bundleDigest = "sha256:" + createHash("sha256").update(jcs({ metadata, modules }), "utf-8").digest("hex");
const buildInfo = {
  name: "build_info.js",
  module: `export const BUNDLE_DIGEST = ${JSON.stringify(bundleDigest)};\nexport const APP_VERSION = ${JSON.stringify(pkg.version)};\n`,
};
writeFileSync(join(srcDir, "build_info.js"), buildInfo.module);
writeFileSync(join(distDir, "bundle.json"), JSON.stringify({ metadata, modules: [...modules, buildInfo] }));
writeFileSync(join(distDir, "bundle_digest.txt"), bundleDigest + "\n");
console.log(`bundle: ${modules.length + 1} modules, digest ${bundleDigest}`);
