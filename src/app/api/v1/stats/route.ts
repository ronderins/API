import { NextRequest, NextResponse } from "next/server";
import { repository } from "@/lib/store";
import { getRequestId } from "@/lib/auth-helper";
import { proxyToRust } from "@/lib/backend-bridge";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  const requestId = getRequestId(request);

  const rustRes = await proxyToRust("/api/v1/stats", { method: "GET" });
  if (rustRes.success && rustRes.data) {
    return NextResponse.json(
      {
        ...rustRes.data,
        bridge: "connected",
      },
      {
        status: 200,
        headers: { "x-request-id": requestId, "x-engine": "rust-axum" },
      }
    );
  }

  const stats = await repository.getStats();

  return NextResponse.json(
    {
      ...stats,
      uptime: process.uptime(),
      service: "zk-identity-api",
      engine: "nextjs-embedded",
      version: "0.1.0",
    },
    {
      status: 200,
      headers: { "x-request-id": requestId, "x-engine": "nextjs-embedded" },
    }
  );
}
