import { describe, expect, it } from "vitest";
import { isBlockedIp, assertPublicHost, realNet } from "../src/lib/agent/net";

describe("SSRF guard", () => {
  it.each(["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "0.0.0.0", "::1", "fd00::1", "::ffff:127.0.0.1", "100.64.0.1"])("blocks %s", (ip) => {
    expect(isBlockedIp(ip)).toBe(true);
  });
  it("allows public IPs", () => {
    expect(isBlockedIp("8.8.8.8")).toBe(false);
  });
  it("rejects localhost and metadata targets", async () => {
    await expect(assertPublicHost("localhost")).rejects.toThrow();
    await expect(realNet.safeFetch("http://169.254.169.254/latest/meta-data")).rejects.toThrow();
    await expect(realNet.safeFetch("http://example.com:8080/")).rejects.toThrow();
  });
});
