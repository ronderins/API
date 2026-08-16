/**
 * Seamless Bridge between Next.js frontend/routes and the Rust API backend.
 * Checks for RUST_API_URL or defaults to local embedded cryptographic engine.
 */

export const RUST_API_BASE =
  process.env.RUST_API_URL?.trim() || "http://127.0.0.1:8080";

export async function proxyToRust(
  path: string,
  options: {
    method: "GET" | "POST";
    headers?: Record<string, string>;
    body?: unknown;
  }
): Promise<{ success: boolean; data?: any; status: number; headers?: Headers }> {
  try {
    const targetUrl = `${RUST_API_BASE}${path}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 1200); // Fast timeout to fallback if Rust isn't running locally

    const res = await fetch(targetUrl, {
      method: options.method,
      headers: {
        "Content-Type": "application/json",
        ...(options.headers || {}),
      },
      body: options.body ? JSON.stringify(options.body) : undefined,
      signal: controller.signal,
    });

    clearTimeout(timeoutId);
    const data = await res.json().catch(() => null);
    return {
      success: true,
      data,
      status: res.status,
      headers: res.headers,
    };
  } catch {
    // Rust API is offline or unreachable -> fallback to embedded engine
    return { success: false, status: 503 };
  }
}
