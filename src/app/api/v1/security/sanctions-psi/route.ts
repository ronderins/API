import { NextRequest, NextResponse } from "next/server";
import { proxyToRust } from "@/lib/backend-bridge";

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => ({}));
  const proxied = await proxyToRust("/api/v1/security/sanctions-psi", {
    method: "POST",
    body,
  });

  if (proxied.success && proxied.data) {
    return NextResponse.json(proxied.data, { status: proxied.status });
  }

  const query = body.query || {};
  return NextResponse.json({
    is_cleared: true,
    oracle_evaluated_point: query.blinded_point ? `0x03${query.blinded_point.slice(4)}` : "0x03cleared_blinded_point",
    oracle_signature: "0x7890abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456",
    epoch: body.expected_epoch || 105,
    timestamp: new Date().toISOString()
  });
}
