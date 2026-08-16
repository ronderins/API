import { NextRequest, NextResponse } from "next/server";
import { getRequestId, checkApiKeyAuth } from "@/lib/auth-helper";
import { proxyToRust } from "@/lib/backend-bridge";
import { repository } from "@/lib/store";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  const requestId = getRequestId(request);

  const authError = checkApiKeyAuth(request, requestId);
  if (authError) {
    return authError;
  }

  // Attempt proxying to Rust Backend
  const apiKey = request.headers.get("x-api-key") || "";
  const rustRes = await proxyToRust("/api/v1/metrics", {
    method: "GET",
    headers: {
      "x-api-key": apiKey,
    },
  });

  if (rustRes.success) {
    return NextResponse.json(rustRes.data, {
      status: rustRes.status,
      headers: { "x-request-id": requestId },
    });
  }

  // Fallback to Next.js memory repository
  const metrics = await repository.getMetrics();
  return NextResponse.json(metrics, {
    status: 200,
    headers: { "x-request-id": requestId },
  });
}
