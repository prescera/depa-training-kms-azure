// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.

import { createGovernance, makeInfoEndpoint, ServiceDescriptor } from "../packages/depa-ccf-common/src/index";
import { APP_VERSION, BUNDLE_DIGEST } from "./build_info";
import { PEER_NAME, SERVICE_NAME } from "./constants";
import { datasetGovernanceActions } from "./datasets";
import { getOidcSettings, oidcGovernanceActions, oidcSigningKey } from "./oidc";

export const SERVICE: ServiceDescriptor = {
  name: SERVICE_NAME,
  version: APP_VERSION,
  bundleDigest: BUNDLE_DIGEST,
  peerName: PEER_NAME,
  actions: [...datasetGovernanceActions, ...oidcGovernanceActions],
  onBootstrap: () => {
    oidcSigningKey.create();
  },
};

export const governance = createGovernance(SERVICE);

export const info = makeInfoEndpoint(SERVICE, () => ({
  oidc_issuer: getOidcSettings()?.issuer_url ?? null,
  oidc_jwks: oidcSigningKey.jwks(),
}));
