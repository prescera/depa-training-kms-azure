// Copyright (c) Microsoft Corporation.
// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.

import { nodeResolve } from "@rollup/plugin-node-resolve";
import typescript from "@rollup/plugin-typescript";

// The app is emitted as one module (dist/src/index.js). build_info.js is kept
// external: build_bundle.js generates it after computing the bundle digest.
export default {
  input: "src/index.ts",
  external: (id) => /(^|\/)build_info(\.js)?$/.test(id),
  output: {
    file: "dist/src/index.js",
    format: "es",
    paths: (id) => (/(^|\/)build_info(\.js)?$/.test(id) ? "./build_info.js" : id),
  },
  plugins: [nodeResolve(), typescript({ tsconfig: "./tsconfig.json", noEmitOnError: true })],
};
