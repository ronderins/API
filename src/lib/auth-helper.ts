import { NextRequest, NextResponse } from "next/server";
import { v4 as uuidv4 } from "uuid";
import { constantTimeEquals } from "./zk-core";

export function getRequestId(request: NextRequest): string {
  const reqId = request.headers.get("x-request-id");
  if (reqId && reqId.trim().length > 0) {
    return reqId.trim();
  }
  return uuidv4();
}

export function checkApiKeyAuth(request: NextRequest, requestId: string): NextResponse | null {
  const keyVar = (process.env.API_KEY || process.env.API_KEYS || "").trim();
  const configuredKeys = keyVar
    .split(",")
    .map((k) => k.trim())
    .filter((k) => k.length > 0);

  if (configuredKeys.length === 0) {
    return null; // No key configured -> public development mode allowed
  }

  const clientApiKey = request.headers.get("x-api-key")?.trim() || "";
  const authHeader = request.headers.get("authorization")?.trim() || "";
  const bearerKey = authHeader.toLowerCase().startsWith("bearer ")
    ? authHeader.slice(7).trim()
    : "";

  const effectiveKey = clientApiKey || bearerKey;

  if (!effectiveKey) {
    return NextResponse.json(
      {
        error: {
          code: "UNAUTHORIZED",
          message: "A valid API key or Bearer token is required.",
          request_id: requestId,
        },
      },
      {
        status: 401,
        headers: { "x-request-id": requestId },
      }
    );
  }

  const isAuthorized = configuredKeys.some((configuredKey) =>
    constantTimeEquals(configuredKey, effectiveKey)
  );

  if (!isAuthorized) {
    return NextResponse.json(
      {
        error: {
          code: "UNAUTHORIZED",
          message: "Invalid API key provided.",
          request_id: requestId,
        },
      },
      {
        status: 401,
        headers: { "x-request-id": requestId },
      }
    );
  }

  return null;
}
