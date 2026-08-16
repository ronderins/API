import { NextRequest, NextResponse } from "next/server";
import { getRequestId, checkApiKeyAuth } from "@/lib/auth-helper";
import { proxyToRust } from "@/lib/backend-bridge";
import { verifyMerkleInclusionProof } from "@/lib/zk-core";

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

  const { leaf_hash, inclusion_path, expected_root } = body;

  const hex64Regex = /^[a-f0-9]{64}$/i;
  if (
    !leaf_hash ||
    typeof leaf_hash !== "string" ||
    !hex64Regex.test(leaf_hash.trim()) ||
    !expected_root ||
    typeof expected_root !== "string" ||
    !hex64Regex.test(expected_root.trim()) ||
    !Array.isArray(inclusion_path) ||
    inclusion_path.length > 64
  ) {
    return NextResponse.json(
      {
        error: {
          code: "VALIDATION_ERROR",
          message: "Fields 'leaf_hash' (64 hex), 'expected_root' (64 hex), and valid 'inclusion_path' array (<=64 items) are required.",
          request_id: requestId,
        },
      },
      {
        status: 422,
        headers: { "x-request-id": requestId },
      }
    );
  }

  const cleanLeaf = leaf_hash.trim().toLowerCase();
  const cleanRoot = expected_root.trim().toLowerCase();

  // Attempt proxying to Rust Backend
  const apiKey = request.headers.get("x-api-key") || "";
  const rustRes = await proxyToRust("/api/v1/verify-merkle", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": apiKey,
    },
    body: {
      leaf_hash: cleanLeaf,
      inclusion_path,
      expected_root: cleanRoot,
    },
  });

  if (rustRes.success && rustRes.data) {
    return NextResponse.json(rustRes.data, {
      status: rustRes.status || 200,
      headers: { "x-request-id": requestId },
    });
  }

  // Cryptographic fallback Merkle verification in Next.js
  const isValid = verifyMerkleInclusionProof(cleanLeaf, inclusion_path, cleanRoot);

  return NextResponse.json(
    {
      is_valid: isValid,
      leaf_hash: cleanLeaf,
      expected_root: cleanRoot,
      path_depth: inclusion_path.length,
      timestamp: new Date().toISOString(),
    },
    {
      status: 200,
      headers: { "x-request-id": requestId },
    }
  );
}
