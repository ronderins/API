import { NextRequest, NextResponse } from "next/server";
import { validate as validateUuid } from "uuid";
import { repository } from "@/lib/store";
import { getRequestId, checkApiKeyAuth } from "@/lib/auth-helper";
import { proxyToRust } from "@/lib/backend-bridge";

export const dynamic = "force-dynamic";

export async function GET(
  request: NextRequest,
  props: { params: Promise<{ id: string }> }
) {
  const requestId = getRequestId(request);
  const { id } = await props.params;

  const authError = checkApiKeyAuth(request, requestId);
  if (authError) {
    return authError;
  }

  if (!id || !validateUuid(id)) {
    return NextResponse.json(
      {
        error: {
          code: "PROOF_NOT_FOUND",
          message: "The requested proof does not exist.",
          request_id: requestId,
        },
      },
      {
        status: 404,
        headers: { "x-request-id": requestId },
      }
    );
  }

  const apiKey = request.headers.get("x-api-key") || "";
  const rustRes = await proxyToRust(`/api/v1/proofs/${id}`, {
    method: "GET",
    headers: {
      "x-request-id": requestId,
      ...(apiKey ? { "x-api-key": apiKey } : {}),
    },
  });

  if (rustRes.success && rustRes.data) {
    return NextResponse.json(rustRes.data, {
      status: rustRes.status,
      headers: { "x-request-id": requestId, "x-engine": "rust-axum" },
    });
  }

  try {
    const proof = await repository.getProof(id);
    if (!proof) {
      return NextResponse.json(
        {
          error: {
            code: "PROOF_NOT_FOUND",
            message: "The requested proof does not exist.",
            request_id: requestId,
          },
        },
        {
          status: 404,
          headers: { "x-request-id": requestId },
        }
      );
    }

    return NextResponse.json(proof, {
      status: 200,
      headers: { "x-request-id": requestId, "x-engine": "nextjs-embedded" },
    });
  } catch (err) {
    console.error("[ZK-API] Proof lookup failed:", err);
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
