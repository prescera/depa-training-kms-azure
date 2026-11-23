// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.
//
// Service signing keys (spec §5). Generated inside CCF; private keys live in
// non-public (ledger-encrypted) tables and are never returned by any endpoint.

import { ccf } from "@microsoft/ccf-app/global";
import { ApiError } from "./errors";
import { EcPublicJwk, jwkThumbprint, signJwsEs256 } from "./jws";
import { JsonTable } from "./kv";

export interface PrivateSigningKey {
  kid: string;
  private_key_pem: string;
}

export interface Es256KeyPair {
  jwk: EcPublicJwk & { kid: string; alg: "ES256"; use: "sig" };
  private_key_pem: string;
}

/** Generates a P-256 key pair; kid is the RFC 7638 thumbprint. */
export function generateEs256KeyPair(): Es256KeyPair {
  const kp = ccf.crypto.generateEcdsaKeyPair("secp256r1");
  const pub = ccf.crypto.pubPemToJwk(kp.publicKey);
  const base: EcPublicJwk = { kty: "EC", crv: "P-256", x: pub.x, y: pub.y };
  const kid = jwkThumbprint(base);
  return { jwk: { ...base, kid, alg: "ES256", use: "sig" }, private_key_pem: kp.privateKey };
}

/**
 * A named signing key: public JWKS in a public table, private key in a
 * private table. Used for the service key and (KMS) the OIDC issuer key.
 */
export class SigningKeyStore {
  private readonly priv: JsonTable<PrivateSigningKey>;
  private readonly pub: JsonTable<Array<Es256KeyPair["jwk"]>>;

  constructor(name: string) {
    this.priv = new JsonTable<PrivateSigningKey>(`depa.private.${name}`);
    this.pub = new JsonTable<Array<Es256KeyPair["jwk"]>>(`public:depa.${name}_jwks`);
  }

  exists(): boolean {
    return this.priv.has("current");
  }

  /** Creates the key; fails if one already exists. */
  create(): Es256KeyPair["jwk"] {
    if (this.exists()) throw ApiError.conflict("signing key already exists");
    const kp = generateEs256KeyPair();
    this.priv.set("current", { kid: kp.jwk.kid, private_key_pem: kp.private_key_pem });
    this.pub.set("jwks", [kp.jwk]);
    return kp.jwk;
  }

  jwks(): Array<Es256KeyPair["jwk"]> {
    return this.pub.get("jwks") ?? [];
  }

  /** Signs `payload` as a compact ES256 JWS with header {alg, typ, kid}. */
  sign(typ: string, payload: unknown): string {
    const key = this.priv.get("current");
    if (!key) throw ApiError.conflict("service is not bootstrapped (no signing key)", "not_bootstrapped");
    return signJwsEs256({ typ, kid: key.kid }, payload, key.private_key_pem);
  }
}

export const serviceSigningKey = new SigningKeyStore("service_signing_key");
