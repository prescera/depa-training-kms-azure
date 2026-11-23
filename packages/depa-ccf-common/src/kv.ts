// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.

import { ccf, KvMap } from "@microsoft/ccf-app/global";

/**
 * A CCF KV map with string keys and JSON values.
 *
 * Naming: tables whose name starts with "public:" are stored in clear in the
 * ledger (auditable); all other tables are encrypted with the ledger secret
 * and are used only for private key material.
 */
export class JsonTable<V> {
  constructor(public readonly name: string) {}

  private get map(): KvMap {
    return ccf.kv[this.name];
  }

  get(key: string): V | undefined {
    const raw = this.map.get(ccf.strToBuf(key));
    return raw === undefined ? undefined : (JSON.parse(ccf.bufToStr(raw)) as V);
  }

  has(key: string): boolean {
    return this.map.has(ccf.strToBuf(key));
  }

  set(key: string, value: V): void {
    this.map.set(ccf.strToBuf(key), ccf.strToBuf(JSON.stringify(value)));
  }

  delete(key: string): void {
    this.map.delete(ccf.strToBuf(key));
  }

  forEach(fn: (value: V, key: string) => void): void {
    this.map.forEach((v, k) => fn(JSON.parse(ccf.bufToStr(v)) as V, ccf.bufToStr(k)));
  }

  entries(): Array<[string, V]> {
    const out: Array<[string, V]> = [];
    this.forEach((v, k) => out.push([k, v]));
    return out;
  }

  /** Sequence number of the last committed write of `key`, if any. */
  versionOf(key: string): number | undefined {
    return this.map.getVersionOfPreviousWrite(ccf.strToBuf(key));
  }
}
