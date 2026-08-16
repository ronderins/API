import { NextRequest, NextResponse } from "next/server";
import { repository } from "@/lib/store";
import { getRequestId } from "@/lib/auth-helper";
import { proxyToRust } from "@/lib/backend-bridge";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  const requestId = getRequestId(request);

  // Check Rust backend first
  const rustCheck = await proxyToRust("/healthz", { method: "GET" });
  if (rustCheck.success && rustCheck.data) {
    return NextResponse.json(
      {
        status: "ok",
        service: "zk-identity-api",
        engine: "Rust Backend (Axum/Tokio)",
        rust_status: rustCheck.data,
      },
      {
        status: 200,
        headers: { "x-request-id": requestId },
      }
    );
  }

  const isHealthy = await repository.healthCheck();
  if (!isHealthy) {
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

  return NextResponse.json(
    {
      status: "ok",
      service: "zk-identity-api",
      engine: "Next.js Cryptographic Engine (Fallback Active)",
    },
    {
      status: 200,
      headers: { "x-request-id": requestId },
    }
  );
}
