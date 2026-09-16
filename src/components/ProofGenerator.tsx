"use client";

import React, { useState, useRef, useEffect } from "react";
import gsap from "gsap";
import {
  ShieldCheck,
  ArrowRight,
  Copy,
  Check,
  Hash,
  Shuffle,
  CheckCircle2,
  AlertCircle,
  Code2,
  Terminal,
  Zap,
  Clock,
  Play,
  RotateCcw,
  FileCheck2,
  Layers,
  ShieldAlert,
  Cpu,
  Globe,
  Flag,
  Shield,
  UserCheck,
  AlertTriangle,
  Lock
} from "lucide-react";
import { animateCryptoStream, animateVerificationSuccess } from "@/lib/gsap-animations";
import type { VerifyResponse, ErrorResponse } from "../types";

interface ProofGeneratorProps {
  onProofCreated: (proof: VerifyResponse) => void;
}

export const ProofGenerator: React.FC<ProofGeneratorProps> = ({ onProofCreated }) => {
  const [userId, setUserId] = useState("user-alice-9842");
  const [docHash, setDocHash] = useState("a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90");
  const [ageThreshold, setAgeThreshold] = useState(18);
  const [apiKey, setApiKey] = useState("");
  const [customRequestId, setCustomRequestId] = useState("");
  const [loading, setLoading] = useState(false);
  const [response, setResponse] = useState<VerifyResponse | null>(null);
  const [responseStatus, setResponseStatus] = useState<number | null>(null);
  const [latencyMs, setLatencyMs] = useState<number | null>(null);
  const [error, setError] = useState<ErrorResponse | string | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [sampleDocumentText, setSampleDocumentText] = useState("");
  const [codeLang, setCodeLang] = useState<"curl" | "rust" | "ts" | "python" | "solidity">("curl");
  const [activeTabSubView, setActiveTabSubView] = useState<"response" | "calldata" | "audit">("response");

  const responseBoxRef = useRef<HTMLDivElement>(null);
  const errorBoxRef = useRef<HTMLDivElement>(null);
  const commitmentTextRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (response && responseBoxRef.current) {
      animateVerificationSuccess(responseBoxRef.current);
      if (response.commitment && commitmentTextRef.current) {
        animateCryptoStream(commitmentTextRef.current, response.commitment, 0.5);
      }
    }
  }, [response]);

  useEffect(() => {
    if (error && errorBoxRef.current) {
      gsap.fromTo(
        errorBoxRef.current,
        { opacity: 0, y: 12, scale: 0.99 },
        { opacity: 1, y: 0, scale: 1, duration: 0.3, ease: "power3.out" }
      );
    }
  }, [error]);

  const handleCopy = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(label);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const handlePreset = (preset: "eidas_18" | "us_regulated_21" | "senior_65" | "sanctions_check" | "invalid_hash" | "out_of_bounds") => {
    setError(null);
    setResponse(null);
    setResponseStatus(null);
    setLatencyMs(null);

    if (preset === "eidas_18") {
      setUserId("eidas-subject-de-9988");
      setDocHash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
      setAgeThreshold(18);
    } else if (preset === "us_regulated_21") {
      setUserId("customer-clara-210");
      setDocHash("8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4");
      setAgeThreshold(21);
    } else if (preset === "senior_65") {
      setUserId("senior-david-1958");
      setDocHash("ca978112ca1bbdcafac231b39a23dc4da7860814966401e97ec17ec6a5362f7b");
      setAgeThreshold(65);
    } else if (preset === "sanctions_check") {
      setUserId("compliance-check-ofac-441");
      setDocHash("7c1b4e9f0a2d5e8b3c6f9a1d4e7b0c3f6a9d2e5b8c1f4a7d0e3b6f9a2c5e8b1d");
      setAgeThreshold(18);
    } else if (preset === "invalid_hash") {
      setUserId("attacker-user");
      setDocHash("invalid_short_hash_123");
      setAgeThreshold(18);
    } else if (preset === "out_of_bounds") {
      setUserId("user-edge-case");
      setDocHash("a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90");
      setAgeThreshold(180);
    }
  };

  const handleComputeHashFromDoc = async () => {
    if (!sampleDocumentText) return;
    const encoder = new TextEncoder();
    const data = encoder.encode(sampleDocumentText);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
    setDocHash(hashHex);
  };

  const handleGenerateRandomHex = () => {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    const hex = Array.from(array)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    setDocHash(hex);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setResponse(null);
    setResponseStatus(null);
    setLatencyMs(null);

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (apiKey.trim()) {
      headers["x-api-key"] = apiKey.trim();
    }
    if (customRequestId.trim()) {
      headers["x-request-id"] = customRequestId.trim();
    }

    const startTime = performance.now();

    try {
      const res = await fetch("/api/v1/verify", {
        method: "POST",
        headers,
        body: JSON.stringify({
          user_id: userId,
          doc_hash: docHash,
          age_threshold: Number(ageThreshold),
        }),
      });

      const elapsed = Math.round(performance.now() - startTime);
      setLatencyMs(elapsed);
      setResponseStatus(res.status);

      const data = await res.json();
      if (!res.ok) {
        setError(data as ErrorResponse);
      } else {
        setResponse(data as VerifyResponse);
        onProofCreated(data as VerifyResponse);
      }
    } catch (err: unknown) {
      setLatencyMs(Math.round(performance.now() - startTime));
      setError(err instanceof Error ? err.message : "Network error");
    } finally {
      setLoading(false);
    }
  };

  // Code generator templates
  const reqBodyObj = { user_id: userId, doc_hash: docHash, age_threshold: Number(ageThreshold) };
  const reqBodyJson = JSON.stringify(reqBodyObj);

  const getCodeSnippet = () => {
    if (codeLang === "curl") {
      return `curl -X POST http://localhost:3000/api/v1/verify \\
  -H "Content-Type: application/json"${apiKey.trim() ? ` \\\n  -H "x-api-key: ${apiKey.trim()}"` : ""}${customRequestId.trim() ? ` \\\n  -H "x-request-id: ${customRequestId.trim()}"` : ""} \\
  -d '${reqBodyJson}'`;
    }

    if (codeLang === "rust") {
      return `// Rust (reqwest + tokio + zeroize)
use reqwest::Client;
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    let mut req = client.post("http://localhost:3000/api/v1/verify")
        .header("Content-Type", "application/json")
        .json(&json!(${JSON.stringify(reqBodyObj, null, 8)}));

    ${apiKey.trim() ? `req = req.header("x-api-key", "${apiKey.trim()}");` : `// Optional: req = req.header("x-api-key", "...");`}
    let res = req.send().await?;
    println!("Status: {}", res.status());
    println!("Commitment Body: {}", res.text().await?);
    Ok(())
}`;
    }

    if (codeLang === "ts") {
      return `// TypeScript / Node.js
async function verifyPrivacyIdentity() {
  const response = await fetch("http://localhost:3000/api/v1/verify", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",${apiKey.trim() ? `\n      "x-api-key": "${apiKey.trim()}",` : ""}${customRequestId.trim() ? `\n      "x-request-id": "${customRequestId.trim()}",` : ""}
    },
    body: JSON.stringify(${JSON.stringify(reqBodyObj, null, 6)}),
  });

  const result = await response.json();
  console.log("Status:", response.status, result);
}

verifyPrivacyIdentity();`;
    }

    if (codeLang === "python") {
      return `# Python (requests)
import requests

headers = {
    "Content-Type": "application/json",${apiKey.trim() ? `\n    "x-api-key": "${apiKey.trim()}",` : ""}
}

payload = ${JSON.stringify(reqBodyObj, null, 4)}

response = requests.post("http://localhost:3000/api/v1/verify", json=payload, headers=headers)
print("Status:", response.status_code)
print("Response:", response.json())`;
    }

    if (codeLang === "solidity") {
      return `// EVM Solidity On-Chain Verification Calldata
// Function: verifyProof(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[4] input)
// Precompile address: 0x08 (ecPairing)

bytes4 selector = bytes4(keccak256("verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[4])"));
bytes memory calldata = abi.encodeWithSelector(
    selector,
    [0x1a8f...G1A_X, 0x2b4c...G1A_Y],
    [[0x0f1e...G2B_X1, 0x1d2c...G2B_X2], [0x3a4b...G2B_Y1, 0x5c6d...G2B_Y2]],
    [0x7e8f...G1C_X, 0x9a0b...G1C_Y],
    [uint256(${ageThreshold}), uint256(2026), 0x${docHash.slice(0, 32)}, 0x${docHash.slice(32, 64)}]
);`;
    }

    return "";
  };

  return (
    <div id="proof-generator-container" className="aegis-card bg-zinc-900/70 border border-zinc-800 rounded-2xl p-6 sm:p-7 shadow-xl space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-zinc-800/80">
        <div className="flex items-center gap-3.5">
          <div className="p-2.5 rounded-xl bg-emerald-950/50 border border-emerald-800/40">
            <Zap className="w-6 h-6 text-emerald-400 shrink-0 filter drop-shadow-[0_0_8px_rgba(52,211,153,0.8)]" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-zinc-100 tracking-tight">Privacy-Preserving Verification Playground</h2>
            <p className="text-xs text-zinc-400 mt-0.5">
              Interactive request composer with instant cryptographic commitment & token issuance
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="px-3 py-1 text-xs font-mono font-medium rounded-full bg-emerald-950/80 text-emerald-400 border border-emerald-800/60 shadow-sm">
            POST /api/v1/verify
          </span>
        </div>
      </div>

      {/* Quick Scenarios & Presets */}
      <div className="p-4 sm:p-4.5 bg-zinc-950/70 border border-zinc-800/80 rounded-xl space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold text-zinc-300 uppercase tracking-wider font-mono flex items-center gap-1.5">
            <Layers className="w-3.5 h-3.5 text-emerald-400" />
            Interactive Test Presets
          </span>
          <span className="text-[11px] text-zinc-500 font-mono">Autofill standard compliance scenarios</span>
        </div>
        <div className="flex flex-wrap gap-2.5 pt-0.5">
          <button
            type="button"
            onClick={() => handlePreset("eidas_18")}
            className="px-3.5 py-2 rounded-lg bg-zinc-900/90 hover:bg-zinc-800 border border-zinc-800 hover:border-zinc-700 text-zinc-300 hover:text-white text-xs font-medium transition duration-150 cursor-pointer flex items-center gap-2 active:scale-95"
          >
            <Globe className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
            <span>eIDAS 2.0 EU Age (18+)</span>
          </button>
          <button
            type="button"
            onClick={() => handlePreset("us_regulated_21")}
            className="px-3.5 py-2 rounded-lg bg-zinc-900/90 hover:bg-zinc-800 border border-zinc-800 hover:border-zinc-700 text-zinc-300 hover:text-white text-xs font-medium transition duration-150 cursor-pointer flex items-center gap-2 active:scale-95"
          >
            <Flag className="w-3.5 h-3.5 text-blue-400 shrink-0" />
            <span>US Legal Age (21+)</span>
          </button>
          <button
            type="button"
            onClick={() => handlePreset("sanctions_check")}
            className="px-3.5 py-2 rounded-lg bg-zinc-900/90 hover:bg-zinc-800 border border-zinc-800 hover:border-zinc-700 text-zinc-300 hover:text-white text-xs font-medium transition duration-150 cursor-pointer flex items-center gap-2 active:scale-95"
          >
            <Shield className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
            <span>OFAC Sanctions Non-Membership</span>
          </button>
          <button
            type="button"
            onClick={() => handlePreset("senior_65")}
            className="px-3.5 py-2 rounded-lg bg-zinc-900/90 hover:bg-zinc-800 border border-zinc-800 hover:border-zinc-700 text-zinc-300 hover:text-white text-xs font-medium transition duration-150 cursor-pointer flex items-center gap-2 active:scale-95"
          >
            <UserCheck className="w-3.5 h-3.5 text-amber-400 shrink-0" />
            <span>Senior Tier (65+)</span>
          </button>
          <button
            type="button"
            onClick={() => handlePreset("invalid_hash")}
            className="px-3.5 py-2 rounded-lg bg-red-950/40 hover:bg-red-900/50 border border-red-900/60 text-red-300 text-xs font-medium transition duration-150 cursor-pointer flex items-center gap-2 active:scale-95"
          >
            <AlertTriangle className="w-3.5 h-3.5 text-rose-400 shrink-0" />
            <span>Malformed Hash (422)</span>
          </button>
        </div>
      </div>

      {/* Main Form */}
      <form onSubmit={handleSubmit} className="space-y-5">
        <div className="space-y-1.5">
          <label className="block text-xs font-medium text-zinc-300 font-mono">
            User Identifier (`user_id`)
          </label>
          <input
            id="input-user-id"
            type="text"
            value={userId}
            onChange={(e) => setUserId(e.target.value)}
            placeholder="e.g. user-alice-123"
            required
            className="w-full bg-zinc-950 border border-zinc-700/80 rounded-lg px-4 py-2.5 text-sm text-zinc-100 placeholder-zinc-500 focus:outline-none focus:border-emerald-500 font-mono transition"
          />
          <p className="text-[11px] text-zinc-500 pt-0.5 flex items-center gap-1.5">
            <Lock className="w-3 h-3 text-emerald-400 inline shrink-0" />
            <span>Privacy Guarantee: Raw <code className="text-zinc-400 font-mono">user_id</code> is NEVER stored in database. Only its non-reversible SHA-256 digest is retained.</span>
          </p>
        </div>

        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <label className="text-xs font-medium text-zinc-300 font-mono">
              Document Digest (`doc_hash` SHA-256 Hex)
            </label>
            <button
              id="btn-random-hash"
              type="button"
              onClick={handleGenerateRandomHex}
              className="text-[11px] text-emerald-400 hover:text-emerald-300 flex items-center gap-1.5 font-mono cursor-pointer transition hover:underline"
            >
              <Shuffle className="w-3 h-3" /> Random SHA-256
            </button>
          </div>
          <input
            id="input-doc-hash"
            type="text"
            value={docHash}
            onChange={(e) => setDocHash(e.target.value)}
            placeholder="64-character hex digest"
            required
            className="w-full bg-zinc-950 border border-zinc-700/80 rounded-lg px-4 py-2.5 text-xs text-zinc-100 placeholder-zinc-500 focus:outline-none focus:border-emerald-500 font-mono transition"
          />

          {/* Client-side document hasher utility */}
          <div className="p-3.5 sm:p-4 bg-zinc-950/70 border border-zinc-850 rounded-xl space-y-2.5 mt-2.5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-zinc-400 flex items-center gap-2">
                <Hash className="w-3.5 h-3.5 text-emerald-400" /> Client-Side ID Hasher Tool (Simulate local passport/ID hash)
              </span>
              <span className="text-[10px] font-mono text-zinc-500">SubtleCrypto SHA-256</span>
            </div>
            <div className="flex gap-2.5">
              <input
                id="input-sample-doc"
                type="text"
                value={sampleDocumentText}
                onChange={(e) => setSampleDocumentText(e.target.value)}
                placeholder="Type dummy passport/license string (e.g. PASSPORT_US_DOE_JOHN_1995)..."
                className="flex-1 bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-emerald-500 font-mono"
              />
              <button
                id="btn-hash-doc"
                type="button"
                onClick={handleComputeHashFromDoc}
                disabled={!sampleDocumentText}
                className="px-4 py-2 bg-zinc-800 hover:bg-zinc-750 disabled:opacity-40 text-xs font-medium rounded-lg text-zinc-200 transition cursor-pointer whitespace-nowrap active:scale-95"
              >
                Hash &amp; Set
              </button>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-zinc-300 font-mono">
              Age Threshold (`age_threshold`)
            </label>
            <input
              id="input-age-threshold"
              type="number"
              min="0"
              max="130"
              value={ageThreshold}
              onChange={(e) => setAgeThreshold(Number(e.target.value))}
              required
              className="w-full bg-zinc-950 border border-zinc-700/80 rounded-lg px-4 py-2 text-sm text-zinc-100 placeholder-zinc-500 focus:outline-none focus:border-emerald-500 font-mono transition"
            />
          </div>

          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-zinc-300 font-mono">
              API Key (`x-api-key`)
            </label>
            <input
              id="input-api-key"
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="Optional API key"
              className="w-full bg-zinc-950 border border-zinc-700/80 rounded-lg px-4 py-2 text-xs text-zinc-100 placeholder-zinc-500 focus:outline-none focus:border-emerald-500 font-mono transition"
            />
          </div>

          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-zinc-300 font-mono">
              Custom Request ID (`x-request-id`)
            </label>
            <input
              id="input-request-id"
              type="text"
              value={customRequestId}
              onChange={(e) => setCustomRequestId(e.target.value)}
              placeholder="Auto-generated if blank"
              className="w-full bg-zinc-950 border border-zinc-700/80 rounded-lg px-4 py-2 text-xs text-zinc-100 placeholder-zinc-500 focus:outline-none focus:border-emerald-500 font-mono transition"
            />
          </div>
        </div>

        <button
          id="btn-submit-verify"
          type="submit"
          disabled={loading}
          className="w-full py-3.5 px-5 bg-emerald-600 hover:bg-emerald-500 disabled:bg-emerald-800/50 text-white font-semibold text-sm rounded-xl flex items-center justify-center gap-2.5 shadow-lg shadow-emerald-950/50 transition duration-150 cursor-pointer active:scale-[0.99]"
        >
          {loading ? (
            <span className="inline-block animate-spin mr-1 text-base">⟳</span>
          ) : (
            <Play className="w-4 h-4 text-emerald-200 fill-current" />
          )}
          {loading ? "Evaluating Circuit & Minting Proof..." : "Send Request & Evaluate Privacy-Preserving Proof"}
        </button>
      </form>

      {/* Response Box with GSAP Scramble & Ticker */}
      {response && (
        <div ref={responseBoxRef} id="verify-response-box" className="mt-6 p-5 sm:p-6 rounded-xl bg-zinc-950/90 border border-emerald-500/40 space-y-4.5 shadow-xl will-change-transform">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3.5 border-b border-zinc-800">
            <div className="flex items-center gap-2.5">
              <span className="px-3 py-1 rounded-md bg-emerald-950 border border-emerald-800 text-emerald-400 font-mono text-xs font-semibold flex items-center gap-1.5 shadow-sm">
                <Check className="w-3.5 h-3.5" /> HTTP {responseStatus || 201} Created
              </span>
              {latencyMs !== null && (
                <span className="px-2.5 py-1 rounded-md bg-zinc-900 border border-zinc-800 text-zinc-400 font-mono text-[11px] flex items-center gap-1.5">
                  <Clock className="w-3 h-3 text-emerald-400" /> {latencyMs} ms
                </span>
              )}
            </div>

            <div className="flex items-center gap-2">
              {response.proof_id && (
                <button
                  id="btn-copy-proof-id"
                  onClick={() => handleCopy(response.proof_id || "", "proof_id")}
                  className="text-xs text-zinc-400 hover:text-zinc-200 flex items-center gap-1.5 font-mono px-3 py-1.5 rounded-lg bg-zinc-900 border border-zinc-800 hover:border-zinc-700 cursor-pointer transition active:scale-95"
                >
                  {copiedField === "proof_id" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedField === "proof_id" ? "Copied ID" : "Copy Proof ID"}</span>
                </button>
              )}
            </div>
          </div>

          <div className="p-3.5 bg-emerald-950/20 border border-emerald-800/40 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
            <span className="text-emerald-300 font-medium flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>Compliance Status: <strong className="text-emerald-200 font-mono">{response.criteria_met}</strong> (Zero PII Stored)</span>
            </span>
            <div className="flex items-center gap-2">
              <span className="px-2.5 py-0.5 bg-purple-900/60 text-purple-300 font-mono text-[10px] rounded border border-purple-700/50">
                Rust SQLx SQLite
              </span>
              <span className="px-2.5 py-0.5 bg-emerald-900/60 text-emerald-300 font-mono text-[10px] rounded border border-emerald-700/50">
                jwt-simple
              </span>
            </div>
          </div>

          {/* Cryptographic Commitment Animated Display */}
          {response.commitment && (
            <div className="p-3.5 sm:p-4 bg-zinc-900/80 rounded-lg border border-zinc-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-zinc-300 font-medium">Domain-Separated Commitment (`commitment`)</span>
                <button
                  onClick={() => handleCopy(response.commitment || "", "commitment")}
                  className="text-xs text-zinc-400 hover:text-emerald-400 flex items-center gap-1.5 font-mono cursor-pointer transition"
                >
                  {copiedField === "commitment" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedField === "commitment" ? "Copied" : "Copy Commitment"}</span>
                </button>
              </div>
              <div
                ref={commitmentTextRef}
                className="text-xs text-emerald-400 font-mono bg-zinc-950 p-3 rounded-md border border-zinc-800 break-all select-all font-semibold tracking-wide"
              >
                {response.commitment}
              </div>
            </div>
          )}

          {(response.proof_signature || response.signed_token) && (
            <div className="p-3.5 sm:p-4 bg-zinc-900/80 rounded-lg border border-zinc-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-zinc-300 font-medium">proof_signature (Cryptographic HMAC-SHA256 Token)</span>
                <button
                  id="btn-copy-token"
                  onClick={() => handleCopy(response.proof_signature || response.signed_token || "", "signed_token")}
                  className="text-xs text-zinc-400 hover:text-emerald-400 flex items-center gap-1.5 font-mono cursor-pointer transition"
                >
                  {copiedField === "signed_token" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedField === "signed_token" ? "Copied Token" : "Copy Token"}</span>
                </button>
              </div>
              <div className="text-xs text-emerald-400 font-mono bg-zinc-950 p-3 rounded-md border border-zinc-800 break-all select-all max-h-28 overflow-y-auto">
                {response.proof_signature || response.signed_token}
              </div>
            </div>
          )}

          <div className="space-y-2">
            <span className="text-xs font-mono text-zinc-400">Response JSON Body:</span>
            <pre className="text-xs text-emerald-300 font-mono bg-zinc-900/90 p-4 rounded-lg overflow-x-auto border border-zinc-800">
              {JSON.stringify(response, null, 2)}
            </pre>
          </div>
        </div>
      )}

      {/* Error Box */}
      {error && (
        <div ref={errorBoxRef} id="verify-error-box" className="mt-6 p-4 sm:p-5 rounded-xl bg-red-950/30 border border-red-800/50 space-y-3 will-change-transform">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-red-400 text-xs font-semibold">
              <AlertCircle className="w-4 h-4" />
              <span>Request Rejected — Error Handled by Algebraic `ApiError`</span>
            </div>
            {responseStatus && (
              <span className="px-2.5 py-0.5 rounded bg-red-950 border border-red-800 text-red-300 font-mono text-xs font-medium">
                HTTP {responseStatus}
              </span>
            )}
          </div>
          <pre className="text-xs text-red-300 font-mono bg-zinc-900 p-3.5 rounded-lg overflow-x-auto border border-red-900/50">
            {typeof error === "string" ? error : JSON.stringify(error, null, 2)}
          </pre>
        </div>
      )}

      {/* Multi-Language Code Snippets */}
      <div className="mt-6 pt-6 border-t border-zinc-800/80 space-y-3.5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Code2 className="w-4 h-4 text-emerald-400" />
            <span className="text-xs font-semibold text-zinc-200 uppercase tracking-wider font-mono">
              Live SDK &amp; API Request Code Generator
            </span>
          </div>

          <div className="flex items-center gap-1 bg-zinc-950 p-1 rounded-lg border border-zinc-800">
            {(["curl", "rust", "ts", "python", "solidity"] as const).map((lang) => (
              <button
                key={lang}
                type="button"
                onClick={() => setCodeLang(lang)}
                className={`px-3 py-1 rounded text-xs font-mono transition cursor-pointer ${
                  codeLang === lang
                    ? "bg-zinc-800 text-emerald-400 font-semibold shadow-sm"
                    : "text-zinc-400 hover:text-zinc-200"
                }`}
              >
                {lang === "ts" ? "TypeScript" : lang === "curl" ? "cURL" : lang === "solidity" ? "Solidity" : lang.toUpperCase()}
              </button>
            ))}
          </div>
        </div>

        <div className="relative">
          <pre className="text-xs text-zinc-300 font-mono bg-zinc-950 p-4 sm:p-5 rounded-xl overflow-x-auto border border-zinc-800/90 leading-relaxed">
            {getCodeSnippet()}
          </pre>
          <button
            id="btn-copy-code-snippet"
            onClick={() => handleCopy(getCodeSnippet(), "snippet")}
            className="absolute top-3 right-3 px-3 py-1.5 rounded-lg bg-zinc-850 hover:bg-zinc-750 text-zinc-300 text-xs flex items-center gap-1.5 font-mono border border-zinc-750 transition cursor-pointer active:scale-95"
          >
            {copiedField === "snippet" ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedField === "snippet" ? "Copied" : "Copy Code"}</span>
          </button>
        </div>
      </div>
    </div>
  );
};
