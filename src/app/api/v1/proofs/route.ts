import { NextRequest, NextResponse } from "next/server";
import { repository } from "@/lib/store";
import { getRequestId, checkApiKeyAuth } from "@/lib/auth-helper";
import { proxyToRust } from "@/lib/backend-bridge";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  const requestId = getRequestId(request);

  const authError = checkApiKeyAuth(request, requestId);
  if (authError) {
    return authError;
  }

  const apiKey = request.headers.get("x-api-key") || "";
  const rustRes = await proxyToRust("/api/v1/proofs", {
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

  const list = await repository.listProofs(100);
  return NextResponse.json(
    { proofs: list },
    {
      status: 200,
      headers: { "x-request-id": requestId, "x-engine": "nextjs-embedded" },
    }
  );
}
