import { NextRequest, NextResponse } from "next/server";
import { repository } from "@/lib/store";
import { validateVerifyPayload } from "@/lib/zk-core";
import { getRequestId, checkApiKeyAuth } from "@/lib/auth-helper";
import { proxyToRust } from "@/lib/backend-bridge";

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
          message: "The request body could not be parsed.",
          request_id: requestId,
        },
      },
      {
        status: 400,
        headers: { "x-request-id": requestId },
      }
    );
  }

  const { isValid, violations, cleaned } = validateVerifyPayload(body);

  if (!isValid || !cleaned) {
    return NextResponse.json(
      {
        error: {
          code: "VALIDATION_ERROR",
          message: "The request contains invalid fields.",
          request_id: requestId,
          details: violations,
        },
      },
      {
        status: 422,
        headers: { "x-request-id": requestId },
      }
    );
  }

  // Attempt forwarding to Rust API backend
  const apiKey = request.headers.get("x-api-key") || "";
  const rustRes = await proxyToRust("/api/v1/verify", {
    method: "POST",
    headers: {
      "x-request-id": requestId,
      ...(apiKey ? { "x-api-key": apiKey } : {}),
    },
    body: {
      user_id: cleaned.userId,
      doc_hash: cleaned.docHash,
      age_threshold: cleaned.ageThreshold,
    },
  });

  if (rustRes.success && rustRes.data) {
    return NextResponse.json(rustRes.data, {
      status: rustRes.status,
      headers: { "x-request-id": requestId, "x-engine": "rust-axum" },
    });
  }

  // Fallback to embedded Next.js cryptographic repository
  try {
    const proof = await repository.createProof(
      cleaned.userId,
      cleaned.docHash,
      cleaned.ageThreshold
    );

    return NextResponse.json(proof, {
      status: 201,
      headers: { "x-request-id": requestId, "x-engine": "nextjs-embedded" },
    });
  } catch (err) {
    console.error("[ZK-API] Proof creation failed:", err);
    return NextResponse.json(
      {
        error: {
          code: "INTERNAL_ERROR",
          message: "The server could not complete the request.",
          request_id: requestId,
        },
      },
      {
        status: 500,
        headers: { "x-request-id": requestId },
      }
    );
  }
}
