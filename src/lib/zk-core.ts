import crypto from "node:crypto";

/**
 * Computes a standard SHA-256 hexadecimal digest of input data.
 * Matches Rust: hex::encode(Sha256::digest(input))
 */
export function digest(input: string | Buffer): string {
  return crypto.createHash("sha256").update(input).digest("hex");
}

/**
 * Builds domain-separated ZK proof commitment matching the Rust implementation:
 * hasher.update(b"zk-identity-proof-v1\0");
 * hasher.update(user_id.as_bytes());
 * hasher.update([0]);
 * hasher.update(doc_hash.as_bytes());
 * hasher.update([0]);
 * hasher.update(age_threshold.to_string().as_bytes());
 * hasher.update([0]);
 * hasher.update(nonce.as_bytes());
 */
export function buildCommitment(
  userId: string,
  docHash: string,
  ageThreshold: number,
  nonce: string
): string {
  const parts = [
    Buffer.from("zk-identity-proof-v1\0", "utf8"),
    Buffer.from(userId, "utf8"),
    Buffer.from([0]),
    Buffer.from(docHash, "utf8"),
    Buffer.from([0]),
    Buffer.from(ageThreshold.toString(), "utf8"),
    Buffer.from([0]),
    Buffer.from(nonce, "utf8"),
  ];

  return crypto.createHash("sha256").update(Buffer.concat(parts)).digest("hex");
}

/**
 * Constant-time comparison for API keys to prevent timing attacks.
 */
export function constantTimeEquals(a: string, b: string): boolean {
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) {
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Simulates ZK Proof evaluation matching the Rust API:
 * 1. Validates document hash integrity
 * 2. Checks age threshold against simulated witness without revealing birthdate/age
 */
export function simulateZkpAgeVerification(
  docHash: string,
  ageThreshold: number
): { success: boolean; error?: string } {
  const hex64Regex = /^[a-f0-9]{64}$/;
  if (!hex64Regex.test(docHash)) {
    return {
      success: false,
      error: "Invalid document hash: must be 64-character SHA-256 hexadecimal",
    };
  }

  if (ageThreshold < 0 || ageThreshold > 130) {
    return {
      success: false,
      error: "Age threshold out of permissible range [0, 130]",
    };
  }

  return { success: true };
}

/**
 * Generates an HMAC-SHA256 signed JWT token matching the jwt-simple crate implementation in Rust.
 */
export function generateSignedProofToken(
  proofId: string,
  userIdDigest: string,
  docHash: string,
  ageThreshold: number,
  ageVerified: boolean,
  commitment: string
): string {
  const secret =
    process.env.JWT_SECRET || "zkp-identity-verification-master-key-32b";

  const header = {
    alg: "HS256",
    typ: "JWT",
  };

  const nowSecs = Math.floor(Date.now() / 1000);
  const payload = {
    iss: "zk-identity-rust-api",
    sub: userIdDigest,
    iat: nowSecs,
    exp: nowSecs + 30 * 86400,
    proof_id: proofId,
    user_id_digest: userIdDigest,
    document_hash: docHash,
    age_threshold: ageThreshold,
    age_verified: ageVerified,
    commitment,
    zk_predicate: `age >= ${ageThreshold}`,
    simulated_proof_circuit: "Groth16/BN254-AgeCheck-v1",
  };

  const toBase64Url = (obj: object) =>
    Buffer.from(JSON.stringify(obj))
      .toString("base64")
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");

  const headerB64 = toBase64Url(header);
  const payloadB64 = toBase64Url(payload);
  const data = `${headerB64}.${payloadB64}`;

  const signature = crypto
    .createHmac("sha256", secret)
    .update(data)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

  return `${data}.${signature}`;
}

/**
 * Verifies and decodes an HMAC-SHA256 signed JWT token.
 * Uses constant-time signature comparison to prevent timing attacks.
 */
export function verifySignedProofToken(token: string): {
  isValid: boolean;
  payload?: any;
  error?: string;
} {
  if (!token || typeof token !== "string" || token.length > 8192) {
    return { isValid: false, error: "Invalid token format or length" };
  }

  const parts = token.split(".");
  if (parts.length !== 3) {
    return { isValid: false, error: "Invalid JWT segment structure" };
  }

  const [headerB64, payloadB64, signatureB64] = parts;
  const secret = process.env.JWT_SECRET || "zkp-identity-verification-master-key-32b";
  const data = `${headerB64}.${payloadB64}`;

  const expectedSignature = crypto
    .createHmac("sha256", secret)
    .update(data)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

  if (!constantTimeEquals(signatureB64, expectedSignature)) {
    return { isValid: false, error: "Cryptographic signature verification failed" };
  }

  try {
    const payloadJson = Buffer.from(payloadB64, "base64url").toString("utf8");
    const payload = JSON.parse(payloadJson);
    const nowSecs = Math.floor(Date.now() / 1000);
    if (payload.exp && typeof payload.exp === "number" && payload.exp < nowSecs) {
      return { isValid: false, error: "Proof token has expired" };
    }
    return { isValid: true, payload };
  } catch {
    return { isValid: false, error: "Corrupted token payload" };
  }
}

/**
 * Computes a domain-separated SHA-256 Merkle tree parent node hash.
 */
export function computeMerkleNode(leftHash: string, rightHash: string): string {
  const parts = [
    Buffer.from("zk-blake3-merkle-node-v1\0", "utf8"),
    Buffer.from(leftHash, "utf8"),
    Buffer.from(rightHash, "utf8"),
  ];
  return crypto.createHash("sha256").update(Buffer.concat(parts)).digest("hex");
}

/**
 * Verifies Merkle inclusion path against an expected root hash using constant-time comparison.
 */
export function verifyMerkleInclusionProof(
  leafHash: string,
  inclusionPath: Array<{ position: string; hash: string }>,
  expectedRoot: string
): boolean {
  const hex64Regex = /^[a-f0-9]{64}$/i;
  if (!hex64Regex.test(leafHash) || !hex64Regex.test(expectedRoot)) {
    return false;
  }

  if (!Array.isArray(inclusionPath) || inclusionPath.length > 64) {
    return false;
  }

  let currentHash = leafHash.toLowerCase();

  for (const step of inclusionPath) {
    if (!step || typeof step !== "object") return false;
    const stepHash = typeof step.hash === "string" ? step.hash.trim().toLowerCase() : "";
    if (!hex64Regex.test(stepHash)) return false;

    if (step.position === "left") {
      currentHash = computeMerkleNode(stepHash, currentHash);
    } else if (step.position === "right") {
      currentHash = computeMerkleNode(currentHash, stepHash);
    } else {
      return false;
    }
  }

  return constantTimeEquals(currentHash, expectedRoot.toLowerCase());
}

/**
 * Request body validator matching Rust route constraints.
 */
export function validateVerifyPayload(body: unknown): {
  isValid: boolean;
  violations: Record<string, string>;
  cleaned?: { userId: string; docHash: string; ageThreshold: number };
} {
  const violations: Record<string, string> = {};

  if (!body || typeof body !== "object") {
    return { isValid: false, violations: { payload: "must be a JSON object" } };
  }

  const record = body as Record<string, unknown>;
  const rawUserId = typeof record.user_id === "string" ? record.user_id.trim() : "";
  const rawDocHash =
    typeof record.doc_hash === "string" ? record.doc_hash.trim().toLowerCase() : "";
  const rawAge =
    typeof record.age_threshold === "number" ? record.age_threshold : -1;

  if (rawUserId.length < 1 || rawUserId.length > 256) {
    violations.user_id = "must contain between 1 and 256 characters";
  }

  const hex64Regex = /^[a-f0-9]{64}$/;
  if (!hex64Regex.test(rawDocHash)) {
    violations.doc_hash = "must be a 64-character SHA-256 hexadecimal digest";
  }

  if (rawAge < 0 || rawAge > 130 || !Number.isInteger(rawAge)) {
    violations.age_threshold = "must be between 0 and 130";
  }

  if (Object.keys(violations).length > 0) {
    return { isValid: false, violations };
  }

  return {
    isValid: true,
    violations: {},
    cleaned: {
      userId: rawUserId,
      docHash: rawDocHash,
      ageThreshold: rawAge,
    },
  };
}
