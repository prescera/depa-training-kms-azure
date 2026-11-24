import { describe, expect, it } from "@jest/globals";
import { aclKeyMatchesEntraPrincipal, maskAclKey } from "../src/acl";

const OID = "8c4f1e2a-0b6d-4f3e-9a1c-2d7e5b9f0a13";
const TID = "1f0e2d3c-4b5a-6978-8f9e-0a1b2c3d4e5f";

describe("ACL Entra principal matching", () => {
  it.each([
    OID,
    OID.toUpperCase(),
    `  ${OID}  `,
    `${TID}/${OID}`,
    `${TID}:${OID}`,
    `${TID.toUpperCase()}.${OID.toUpperCase()}`,
  ])("matches %s", (key) => {
    expect(aclKeyMatchesEntraPrincipal(key, OID, TID)).toBe(true);
  });

  it.each([
    "",
    OID.slice(0, -1),
    `${OID}0`,
    `x${OID}`,
    `00000000-0000-0000-0000-000000000000/${OID}`,
    "12:AB:34:CD",
  ])("does not match %s", (key) => {
    expect(aclKeyMatchesEntraPrincipal(key, OID, TID)).toBe(false);
  });
});

describe("maskAclKey", () => {
  it("hides identifiers but keeps the shape", () => {
    expect(maskAclKey(`${TID}/${OID}`)).toBe("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx");
    expect(maskAclKey("12:AB:34")).toBe("xx:xx:xx");
  });
});
