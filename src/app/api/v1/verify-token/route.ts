import { NextRequest, NextResponse } from "next/server";
import { getRequestId, checkApiKeyAuth } from "@/lib/auth-helper";
import { proxyToRust } from "@/lib/backend-bridge";
import { verifySignedProofToken } from "@/lib/zk-core";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  const requestId = getRequestId(request);

  // Authentication check if API_KEY is set
  const authError = checkApiKeyAuth(request, requestId);
  if (authError) {
    return authError;
  }

  let body: any;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json(
      {
        error: {
          code: "BAD_REQUEST",
          message: "The request body could not be parsed as valid JSON.",
          request_id: requestId,
        },
      },
      {
        status: 400,
        headers: { "x-request-id": requestId },
      }
    );
  }

  const token = typeof body?.token === "string" ? body.token.trim() : "";
  if (!token) {
    return NextResponse.json(
      {
        error: {
          code: "VALIDATION_ERROR",
          message: "The 'token' field is required and cannot be empty.",
          request_id: requestId,
        },
      },
      {
        status: 422,
        headers: { "x-request-id": requestId },
      }
    );
  }

  // Attempt proxying to Rust Backend
  const apiKey = request.headers.get("x-api-key") || "";
  const rustRes = await proxyToRust("/api/v1/verify-token", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": apiKey,
    },
    body: { token },
  });

  if (rustRes.success && rustRes.data) {
    return NextResponse.json(rustRes.data, {
      status: rustRes.status || 200,
      headers: { "x-request-id": requestId },
    });
  }

  // Cryptographic token verification in Next.js fallback
  const result = verifySignedProofToken(token);
  if (result.isValid && result.payload) {
    const claims = result.payload;
    return NextResponse.json(
      {
        is_valid: true,
        proof_id: claims.proof_id || claims.sub || "standalone-token",
        user_id_digest: claims.user_id_digest || "",
        document_hash: claims.document_hash || "",
        age_threshold: claims.age_threshold || 18,
        verified: claims.age_verified ?? claims.verified ?? true,
        criteria_met: claims.criteria_met || `age_over_${claims.age_threshold || 18}`,
        commitment: claims.commitment || "",
        zk_predicate: claims.zk_predicate || `age >= ${claims.age_threshold || 18}`,
        simulated_proof_circuit:
          claims.simulated_proof_circuit || "Groth16/BN254-AgeCheck-v1",
        status: "valid",
        message: "Cryptographic token signature and claims verified successfully.",
      },
      { status: 200, headers: { "x-request-id": requestId } }
    );
  }

  return NextResponse.json(
    {
      is_valid: false,
      status: "invalid",
      message: result.error || "The provided token is invalid, corrupted, or signature verification failed.",
      request_id: requestId,
    },
    {
      status: 422,
      headers: { "x-request-id": requestId },
    }
  );
}
