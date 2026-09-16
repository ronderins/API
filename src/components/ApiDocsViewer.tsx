"use client";

import React, { useState, useRef, useEffect } from "react";
import gsap from "gsap";
import { BookOpen, ExternalLink, Code2, Copy, Check } from "lucide-react";

type EndpointTab =
  | "verify"
  | "verify-token"
  | "verify-merkle"
  | "session"
  | "ledger"
  | "metrics"
  | "proofs"
  | "rust-ecosystem"
  | "health";

export const ApiDocsViewer: React.FC = () => {
  const [activeTab, setActiveTab] = useState<EndpointTab>("verify");
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const contentRef = useRef<HTMLDivElement>(null);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  useEffect(() => {
    if (contentRef.current) {
      gsap.fromTo(
        contentRef.current,
        { opacity: 0, y: 10, scale: 0.995 },
        { opacity: 1, y: 0, scale: 1, duration: 0.25, ease: "power3.out" }
      );
    }
  }, [activeTab]);

  const handleTabClick = (tab: EndpointTab) => {
    if (tab === activeTab) return;
    if (contentRef.current) {
      gsap.to(contentRef.current, {
        opacity: 0,
        y: -6,
        duration: 0.14,
        ease: "power2.in",
        onComplete: () => {
          setActiveTab(tab);
        },
      });
    } else {
      setActiveTab(tab);
    }
  };

  return (
    <div id="api-docs-container" className="bg-zinc-900/70 border border-zinc-800 rounded-xl p-6 shadow-xl space-y-6">
      <div className="flex items-center justify-between pb-4 border-b border-zinc-800/80">
        <div className="flex items-center gap-3">
          <BookOpen className="w-8 h-8 text-indigo-400 shrink-0 filter drop-shadow-[0_0_10px_rgba(129,140,248,0.85)]" />
          <div>
            <h2 className="text-lg font-semibold text-zinc-100">REST API Specification</h2>
            <p className="text-xs text-zinc-400">OpenAPI 3.1 compatible endpoints & schema definitions for Aegis engine</p>
          </div>
        </div>

        <a
          href="/openapi.yaml"
          target="_blank"
          rel="noreferrer"
          className="text-xs text-indigo-400 hover:text-indigo-300 flex items-center gap-1 font-mono bg-indigo-950/40 border border-indigo-800/60 px-3 py-1.5 rounded-lg transition"
        >
          <Code2 className="w-3.5 h-3.5" /> openapi.yaml <ExternalLink className="w-3 h-3 ml-0.5" />
        </a>
      </div>

      {/* Tabs */}
      <div className="flex flex-wrap gap-1.5 border-b border-zinc-800 pb-2">
        <button
          onClick={() => handleTabClick("verify")}
          className={`px-3 py-1.5 text-xs font-mono rounded-lg transition duration-200 cursor-pointer flex items-center gap-1.5 ${
            activeTab === "verify"
              ? "bg-zinc-800 text-emerald-400 font-semibold border border-zinc-700 shadow-sm"
              : "text-zinc-400 hover:text-zinc-200"
          }`}
        >
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 font-mono">POST</span>
          /api/v1/verify
        </button>

        <button
          onClick={() => handleTabClick("verify-token")}
          className={`px-3 py-1.5 text-xs font-mono rounded-lg transition duration-200 cursor-pointer flex items-center gap-1.5 ${
            activeTab === "verify-token"
              ? "bg-zinc-800 text-teal-400 font-semibold border border-zinc-700 shadow-sm"
              : "text-zinc-400 hover:text-zinc-200"
          }`}
        >
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-950 text-teal-400 font-mono">POST</span>
          /api/v1/verify-token
        </button>

        <button
          onClick={() => handleTabClick("verify-merkle")}
          className={`px-3 py-1.5 text-xs font-mono rounded-lg transition duration-200 cursor-pointer flex items-center gap-1.5 ${
            activeTab === "verify-merkle"
              ? "bg-zinc-800 text-blue-400 font-semibold border border-zinc-700 shadow-sm"
              : "text-zinc-400 hover:text-zinc-200"
          }`}
        >
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-950 text-blue-400 font-mono">POST</span>
          /api/v1/verify-merkle
        </button>

        <button
          onClick={() => handleTabClick("session")}
          className={`px-3 py-1.5 text-xs font-mono rounded-lg transition duration-200 cursor-pointer flex items-center gap-1.5 ${
            activeTab === "session"
              ? "bg-zinc-800 text-purple-400 font-semibold border border-zinc-700 shadow-sm"
              : "text-zinc-400 hover:text-zinc-200"
          }`}
        >
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-950 text-purple-400 font-mono">GET</span>
          /api/v1/session
        </button>

        <button
          onClick={() => handleTabClick("ledger")}
          className={`px-3 py-1.5 text-xs font-mono rounded-lg transition duration-200 cursor-pointer flex items-center gap-1.5 ${
            activeTab === "ledger"
              ? "bg-zinc-800 text-amber-400 font-semibold border border-zinc-700 shadow-sm"
              : "text-zinc-400 hover:text-zinc-200"
          }`}
        >
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-950 text-amber-400 font-mono">GET</span>
          /api/v1/ledger
        </button>

        <button
          onClick={() => handleTabClick("metrics")}
          className={`px-3 py-1.5 text-xs font-mono rounded-lg transition duration-200 cursor-pointer flex items-center gap-1.5 ${
            activeTab === "metrics"
              ? "bg-zinc-800 text-cyan-400 font-semibold border border-zinc-700 shadow-sm"
              : "text-zinc-400 hover:text-zinc-200"
          }`}
        >
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-400 font-mono">GET</span>
          /api/v1/metrics
        </button>

        <button
          onClick={() => handleTabClick("proofs")}
          className={`px-3 py-1.5 text-xs font-mono rounded-lg transition duration-200 cursor-pointer flex items-center gap-1.5 ${
            activeTab === "proofs"
              ? "bg-zinc-800 text-indigo-400 font-semibold border border-zinc-700 shadow-sm"
              : "text-zinc-400 hover:text-zinc-200"
          }`}
        >
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-indigo-950 text-indigo-400 font-mono">GET</span>
          /api/v1/proofs/&#123;id&#125;
        </button>

        <button
          onClick={() => handleTabClick("rust-ecosystem")}
          className={`px-3 py-1.5 text-xs font-mono rounded-lg transition duration-200 cursor-pointer flex items-center gap-1.5 ${
            activeTab === "rust-ecosystem"
              ? "bg-zinc-800 text-orange-400 font-semibold border border-zinc-700 shadow-sm"
              : "text-zinc-400 hover:text-zinc-200"
          }`}
        >
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-orange-950 text-orange-400 font-mono">GET</span>
          /api/v1/rust-ecosystem
        </button>

        <button
          onClick={() => handleTabClick("health")}
          className={`px-3 py-1.5 text-xs font-mono rounded-lg transition duration-200 cursor-pointer flex items-center gap-1.5 ${
            activeTab === "health"
              ? "bg-zinc-800 text-green-400 font-semibold border border-zinc-700 shadow-sm"
              : "text-zinc-400 hover:text-zinc-200"
          }`}
        >
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-green-950 text-green-400 font-mono">GET</span>
          /healthz
        </button>
      </div>

      {/* Tab Contents with GSAP Transition */}
      <div ref={contentRef} className="will-change-transform">
        {activeTab === "verify" && (
          <div className="space-y-4 text-xs">
            <div>
              <h3 className="font-semibold text-zinc-200 text-sm mb-1">Create Verification Proof</h3>
              <p className="text-zinc-400">
                Generates a Privacy-Preserving cryptographic commitment verifying document digest and age requirement. Raw user ID is never saved to database.
              </p>
            </div>

            <div className="p-3 bg-zinc-950 rounded-lg border border-zinc-800">
              <span className="font-mono text-zinc-400 block mb-1">Headers:</span>
              <code className="text-zinc-300 font-mono block">Content-Type: application/json</code>
              <code className="text-zinc-400 font-mono block">X-API-Key: &lt;optional-api-key&gt;</code>
              <code className="text-zinc-400 font-mono block">Authorization: Bearer &lt;optional-api-key&gt;</code>
            </div>

            <div className="space-y-2">
              <span className="font-semibold text-zinc-300 block">Request Schema (JSON):</span>
              <pre className="bg-zinc-950 p-3 rounded-lg font-mono text-emerald-300 border border-zinc-800 overflow-x-auto">
{`{
  "user_id": "usr_test_1234",
  "document_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "age": 22,
  "criteria_threshold": 18
}`}
              </pre>
            </div>

            <div className="space-y-2">
              <span className="font-semibold text-zinc-300 block">Strict Compliance Response (201 Created):</span>
              <pre className="bg-zinc-950 p-3 rounded-lg font-mono text-emerald-300 border border-zinc-800 overflow-x-auto">
{`{
  "proof_id": "7c6c1d63-6e9e-4e3c-86d4-328e40cc6c04",
  "status": "verified",
  "criteria_met": true,
  "predicate": "age >= 18",
  "commitment": "b2f6d7e9a1b8c3d4dc0af8e9f0b1c2d3a4b5c6d7e8f90a1b2c3d4e5f607182",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "created_at": 1786756800,
  "expires_at": 1786760400
}`}
              </pre>
            </div>
          </div>
        )}

        {activeTab === "verify-token" && (
          <div className="space-y-4 text-xs">
            <div>
              <h3 className="font-semibold text-zinc-200 text-sm mb-1">Verify Signed JWT Proof Token</h3>
              <p className="text-zinc-400">
                Cryptographically verifies the authenticity and claim integrity of a previously minted JWT proof signature token.
              </p>
            </div>

            <div className="space-y-2">
              <span className="font-semibold text-zinc-300 block">Request Schema (JSON):</span>
              <pre className="bg-zinc-950 p-3 rounded-lg font-mono text-teal-300 border border-zinc-800 overflow-x-auto">
{`{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0YTdk...\""
}`}
              </pre>
            </div>

            <div className="space-y-2">
              <span className="font-semibold text-zinc-300 block">Response (200 OK):</span>
              <pre className="bg-zinc-950 p-3 rounded-lg font-mono text-zinc-300 border border-zinc-800 overflow-x-auto">
{`{
  "valid": true,
  "proof_id": "7c6c1d63-6e9e-4e3c-86d4-328e40cc6c04",
  "claims": {
    "sub": "4a7dcc755767f4cadbea8f513bd482838834ad3f888ab6cf6ceb0f6078aa39f1",
    "verified": true,
    "criteria_met": "age_over_18",
    "commitment": "b2f6d7e9a1b8c3d4dc0af8e9f0b1c2d3a4b5c6d7e8f90a1b2c3d4e5f607182",
    "exp": 1786760400
  }
}`}
              </pre>
            </div>
          </div>
        )}

        {activeTab === "verify-merkle" && (
          <div className="space-y-4 text-xs">
            <div>
              <h3 className="font-semibold text-zinc-200 text-sm mb-1">Verify Merkle Inclusion Proof</h3>
              <p className="text-zinc-400">
                Verifies that a specific verification receipt leaf hash is immutably included in the tamper-evident Blake3 Merkle chain root.
              </p>
            </div>

            <div className="space-y-2">
              <span className="font-semibold text-zinc-300 block">Request Schema (JSON):</span>
              <pre className="bg-zinc-950 p-3 rounded-lg font-mono text-blue-300 border border-zinc-800 overflow-x-auto">
{`{
  "leaf_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "inclusion_path": [
    "9a8b7c6d5e4f3a2b1c0def0123456789abcdef0123456789abcdef0123456789"
  ],
  "expected_root": "b2f6d7e9a1b8c3d4dc0af8e9f0b1c2d3a4b5c6d7e8f90a1b2c3d4e5f607182"
}`}
              </pre>
            </div>

            <div className="space-y-2">
              <span className="font-semibold text-zinc-300 block">Response (200 OK):</span>
              <pre className="bg-zinc-950 p-3 rounded-lg font-mono text-emerald-300 border border-zinc-800 overflow-x-auto">
{`{
  "verified": true,
  "computed_root": "b2f6d7e9a1b8c3d4dc0af8e9f0b1c2d3a4b5c6d7e8f90a1b2c3d4e5f607182",
  "matches_ledger_root": true
}`}
              </pre>
            </div>
          </div>
        )}

        {activeTab === "session" && (
          <div className="space-y-4 text-xs">
            <div>
              <h3 className="font-semibold text-zinc-200 text-sm mb-1">One-Time Blind QR Session</h3>
              <p className="text-zinc-400">
                Mints a short-lived UUID challenge nonce with 5-minute in-memory TTL for cross-device authentication.
              </p>
            </div>

            <div className="space-y-2">
              <span className="font-semibold text-zinc-300 block">Response (200 OK):</span>
              <pre className="bg-zinc-950 p-3 rounded-lg font-mono text-purple-300 border border-zinc-800 overflow-x-auto">
{`{
  "session_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "challenge_nonce": "9a8b7c6d5e4f3a2b1c0d",
  "expires_in_seconds": 300,
  "qr_payload": "zkauth://challenge?sid=f47ac10b-58cc-4372-a567-0e02b2c3d479&nonce=9a8b7c6d5e4f3a2b1c0d"
}`}
              </pre>
            </div>
          </div>
        )}

        {activeTab === "ledger" && (
          <div className="space-y-4 text-xs">
            <div>
              <h3 className="font-semibold text-zinc-200 text-sm mb-1">Tamper-Evident Merkle Receipt Ledger</h3>
              <p className="text-zinc-400">
                Retrieves immutable Blake3 Merkle-chain verification receipts and root digest.
              </p>
            </div>

            <div className="space-y-2">
              <span className="font-semibold text-zinc-300 block">Response (200 OK):</span>
              <pre className="bg-zinc-950 p-3 rounded-lg font-mono text-amber-300 border border-zinc-800 overflow-x-auto">
{`{
  "merkle_root": "a4d8c0e123456789abcdef0123456789abcdef0123456789abcdef0123456789",
  "block_height": 42,
  "entries": [
    {
      "index": 41,
      "proof_id": "7c6c1d63-6e9e-4e3c-86d4-328e40cc6c04",
      "leaf_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "timestamp": 1786756800
    }
  ]
}`}
              </pre>
            </div>
          </div>
        )}

        {activeTab === "metrics" && (
          <div className="space-y-4 text-xs">
            <div>
              <h3 className="font-semibold text-zinc-200 text-sm mb-1">Performance & Memory Metrics</h3>
              <p className="text-zinc-400">
                Real-time microsecond latency telemetry and sysinfo process RSS memory monitoring.
              </p>
            </div>

            <div className="space-y-2">
              <span className="font-semibold text-zinc-300 block">Response (200 OK):</span>
              <pre className="bg-zinc-950 p-3 rounded-lg font-mono text-cyan-300 border border-zinc-800 overflow-x-auto">
{`{
  "process_memory_rss_bytes": 14680064,
  "memory_rss_formatted": "14.00 MB",
  "average_proof_latency_us": 142,
  "simd_backend": "blake3-avx512",
  "total_evaluations": 1284,
  "zeroize_cleanup_time_ns": 28
}`}
              </pre>
            </div>
          </div>
        )}

        {activeTab === "proofs" && (
          <div className="space-y-4 text-xs">
            <div>
              <h3 className="font-semibold text-zinc-200 text-sm mb-1">Get Proof & Audit Trail</h3>
              <p className="text-zinc-400">
                Retrieves stored commitment metadata and immutable audit event trail. Returns 404 if proof not found.
              </p>
            </div>

            <div className="space-y-2">
              <span className="font-semibold text-zinc-300 block">Path Parameters:</span>
              <div className="p-3 bg-zinc-950 rounded-lg border border-zinc-800 font-mono">
                <span className="text-indigo-400">id</span>: UUID v4 string (e.g. 7c6c1d63-6e9e-4e3c-86d4-328e40cc6c04)
              </div>
            </div>

            <div className="space-y-2">
              <span className="font-semibold text-zinc-300 block">Response (200 OK):</span>
              <pre className="bg-zinc-950 p-3 rounded-lg font-mono text-zinc-300 border border-zinc-800 overflow-x-auto">
{`{
  "proof_id": "7c6c1d63-6e9e-4e3c-86d4-328e40cc6c04",
  "status": "accepted",
  "user_id_digest": "4a7d...39f1 (SHA-256)",
  "document_hash": "e3b0...b855 (SHA-256)",
  "age_threshold": 18,
  "verified": true,
  "criteria_met": "age_over_18",
  "commitment": "b2f6...a109",
  "proof_signature": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "created_at": "2026-08-14T12:00:00.000Z",
  "audit_trail": [
    {
      "event_id": 1,
      "event_type": "proof_created",
      "metadata": { "version": "zk-identity-proof-v1", "database": "sqlx-in-memory-sqlite" },
      "created_at": "2026-08-14T12:00:00.000Z"
    }
  ]
}`}
              </pre>
            </div>
          </div>
        )}

        {activeTab === "rust-ecosystem" && (
          <div className="space-y-4 text-xs">
            <div>
              <h3 className="font-semibold text-zinc-200 text-sm mb-1">Rust Cryptographic Ecosystem Specifications</h3>
              <p className="text-zinc-400">
                Detailed capabilities of Arkworks, zkSync Boojum, Aleo snarkVM, and Halo2 UltraPLONK modules.
              </p>
            </div>

            <div className="space-y-2">
              <span className="font-semibold text-zinc-300 block">Response (200 OK):</span>
              <pre className="bg-zinc-950 p-3 rounded-lg font-mono text-orange-300 border border-zinc-800 overflow-x-auto">
{`{
  "framework": "Rust Native Cryptography Engine",
  "edition": "2021",
  "runtime": "Axum + Tokio Asynchronous Microservice",
  "supported_ecosystems": [
    "Arkworks (ark-ff, ark-ec, ark-groth16)",
    "zkSync Boojum (SIMD GPU/CPU proving)",
    "Aleo snarkVM (Private programmable state)",
    "Halo2 & UltraPLONK (Plookup lookup arguments)"
  ],
  "performance_benchmarks": {
    "witness_generation_latency_us": 42,
    "snark_verification_latency_us": 118,
    "merkle_root_computation_latency_us": 14,
    "zeroize_cleanup_latency_ns": 25
  }
}`}
              </pre>
            </div>
          </div>
        )}

        {activeTab === "health" && (
          <div className="space-y-4 text-xs">
            <div>
              <h3 className="font-semibold text-zinc-200 text-sm mb-1">Health Check (Public)</h3>
              <p className="text-zinc-400">
                Validates that the database connection and service engine are fully operational.
              </p>
            </div>

            <div className="space-y-2">
              <span className="font-semibold text-zinc-300 block">Response (200 OK):</span>
              <pre className="bg-zinc-950 p-3 rounded-lg font-mono text-green-300 border border-zinc-800 overflow-x-auto">
{`{
  "status": "ok",
  "service": "zk-identity-api",
  "engine": "Axum / Embedded Fallback",
  "uptime_seconds": 3600
}`}
              </pre>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
