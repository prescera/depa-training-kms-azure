// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.
//
// Expected values were produced with the Python `rfc8785` package (the SDK's
// implementation) and match the examples in RFC 8785 §3.2.2–3.2.3.

import { describe, expect, it } from "@jest/globals";
import { canonicalize, digest } from "../src/jcs";

const c = (n: number) => String.fromCharCode(n);
const BS = c(92);

describe("JCS (RFC 8785)", () => {
  it("canonicalizes the RFC 8785 §3.2.2 example", () => {
    const input = {
      numbers: [333333333.33333329, 1e30, 4.5, 2e-3, 1e-27],
      string: c(0x20ac) + "$" + c(0x0f) + c(0x0a) + "A'" + c(0x42) + c(0x22) + c(0x5c) + c(0x5c) + '"/',
      literals: [null, true, false],
    };
    const expected =
      '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"' +
      c(0x20ac) + "$" + BS + "u000f" + BS + "nA'B" + BS + '"' + BS + BS + BS + BS + BS + '"/"}';
    expect(canonicalize(input)).toBe(expected);
  });

  it("sorts keys by UTF-16 code units (RFC 8785 §3.2.3)", () => {
    const input: Record<string, string> = {};
    input[c(0x20ac)] = "Euro Sign";
    input[c(13)] = "Carriage Return";
    input[c(0xfb33)] = "Hebrew";
    input["1"] = "One";
    input[c(0xd83d) + c(0xde00)] = "Emoji";
    input[c(0x80)] = "Control";
    input[c(0xf6)] = "o-umlaut";
    const out = canonicalize(input);
    const values = ["Carriage Return", "One", "Control", "o-umlaut", "Euro Sign", "Emoji", "Hebrew"];
    const positions = values.map((v) => out.indexOf(`"${v}"`));
    expect(positions.every((p) => p > 0)).toBe(true);
    expect([...positions].sort((a, b) => a - b)).toEqual(positions);
  });

  it.each([
    [5e-324, "5e-324"],
    [1.7976931348623157e308, "1.7976931348623157e+308"],
    [9007199254740992, "9007199254740992"],
    [295147905179352830000, "295147905179352830000"],
    [1e21, "1e+21"],
    [0.000001, "0.000001"],
    [1e-7, "1e-7"],
    [333333333.3333333, "333333333.3333333"],
    [-0, "0"],
    [1e-5, "0.00001"],
    [4.0, "4"],
  ])("formats %p as %s", (n, s) => {
    expect(canonicalize(n)).toBe(s);
  });

  it("rejects non-finite numbers and lone surrogates", () => {
    expect(() => canonicalize(NaN)).toThrow();
    expect(() => canonicalize(Infinity)).toThrow();
    expect(() => canonicalize(c(0xd800))).toThrow();
    expect(() => canonicalize({ [c(0xdc00)]: 1 })).toThrow();
  });

  it("matches the Python rfc8785 digest", () => {
    const v = { b: [1, { z: null, a: 1e-7 }], a: "x" };
    expect(canonicalize(v)).toBe('{"a":"x","b":[1,{"a":1e-7,"z":null}]}');
    expect(digest(v)).toBe("sha256:7cada1e861e7fb856b611e1761898cb96fc407ec5e65f858150376f8946ba2e2");
  });
});
