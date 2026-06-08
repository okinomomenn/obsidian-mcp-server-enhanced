/**
 * @fileoverview RFC 7636 PKCE S256 verification.
 * Computes base64url(sha256(verifier)) and compares to the challenge sent at /authorize.
 */

import { createHash, timingSafeEqual } from "node:crypto";

/** Returns true iff S256(verifier) === challenge. Constant-time comparison. */
export function verifyS256Challenge(verifier: string, challenge: string): boolean {
  const computed = createHash("sha256").update(verifier).digest().toString("base64url");
  const a = Buffer.from(computed);
  const b = Buffer.from(challenge);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
