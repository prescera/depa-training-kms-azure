// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.

import * as ccfapp from "@microsoft/ccf-app";
import { createPrivateKey, generateKeyPairSync, randomUUID, sign } from "crypto";

type Store = Map<string, Map<string, unknown>>;
const g = globalThis as unknown as { __ccfKv: Store };

export function resetKv(): void {
  g.__ccfKv.clear();
}

function snapshot(): Store {
  const s: Store = new Map();
  for (const [k, m] of g.__ccfKv.entries()) s.set(k, new Map(m));
  return s;
}

export function b64url(b: Buffer | Uint8Array | string): string {
  return Buffer.from(b as Uint8Array).toString("base64url");
}

export interface FakeRequestInit {
  body?: unknown;
  rawBody?: string;
  params?: Record<string, string>;
  query?: string;
  caller?: unknown;
  headers?: Record<string, string>;
}

export function fakeRequest(init: FakeRequestInit = {}): ccfapp.Request {
  const text = init.rawBody ?? (init.body === undefined ? "" : JSON.stringify(init.body));
  return {
    headers: init.headers ?? {},
    params: init.params ?? {},
    url: "",
    path: "",
    route: "",
    query: init.query ?? "",
    method: "POST",
    hostname: "localhost",
    body: {
      text: () => text,
      json: () => JSON.parse(text),
      arrayBuffer: () => new TextEncoder().encode(text).buffer as ArrayBuffer,
    },
    caller: (init.caller ?? { policy: "no_auth" }) as ccfapp.AuthnIdentity,
  };
}

export interface CallResult {
  status: number;
  body: any;
}

/** Invokes an endpoint with CCF semantics: KV writes are discarded on non-2xx. */
export function call(fn: ccfapp.EndpointFn, req: ccfapp.Request): CallResult {
  const before = snapshot();
  const res = fn(req);
  const status = res.statusCode ?? 200;
  if (status < 200 || status >= 300) {
    g.__ccfKv.clear();
    for (const [k, m] of before.entries()) g.__ccfKv.set(k, m as never);
  }
  return { status, body: res.body };
}

export class TestParty {
  readonly privateKeyPem: string;
  readonly jwk: { kty: "EC"; crv: "P-256"; x: string; y: string; kid: string };

  constructor(
    readonly party_id: string,
    readonly roles: string[],
    readonly kid = "k1",
  ) {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    this.privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" }) as string;
    const j = publicKey.export({ format: "jwk" }) as { x: string; y: string };
    this.jwk = { kty: "EC", crv: "P-256", x: j.x, y: j.y, kid };
  }

  record(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      party_id: this.party_id,
      name: this.party_id,
      roles: this.roles,
      signing_keys: [this.jwk],
      hpke_public_keys: [{ kid: "h1", x25519: b64url(Buffer.alloc(32, 7)) }],
      status: "active",
      ...overrides,
    };
  }

  jws(header: Record<string, unknown>, payload: unknown, opts: { der?: boolean } = {}): string {
    const h = b64url(JSON.stringify({ alg: "ES256", ...header }));
    const p = b64url(JSON.stringify(payload));
    const sig = sign("sha256", Buffer.from(`${h}.${p}`), {
      key: createPrivateKey(this.privateKeyPem),
      dsaEncoding: opts.der ? "der" : "ieee-p1363",
    });
    return `${h}.${p}.${b64url(sig)}`;
  }

  signRequest(aud: string, op: string, body: unknown, opts: { iat?: number; jti?: string; der?: boolean } = {}): string {
    return this.jws(
      { kid: `${this.party_id}#${this.kid}`, typ: "depa-request+jws" },
      { aud, op, iat: opts.iat ?? Math.floor(Date.now() / 1000), jti: opts.jti ?? randomUUID(), body },
      { der: opts.der },
    );
  }
}
