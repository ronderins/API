"use client";

import React, { useEffect, useRef } from "react";
import gsap from "gsap";
import {
  X,
  ExternalLink,
  ShieldCheck,
  Code2,
  Lock,
  Download,
  Terminal,
  Cpu,
  Check,
  Copy,
  Layers,
  Sparkles,
  FileCode2,
  BookOpen,
  Calendar,
  User,
  Zap,
  Globe,
  Database,
  KeyRound,
} from "lucide-react";

export type FooterModalType =
  | "how_it_works"
  | "api_docs"
  | "security_lab"
  | "source_code"
  | "zero_pii"
  | "creator_profile"
  | "public_testing_guide"
  | null;

interface FooterModalProps {
  type: FooterModalType;
  onClose: () => void;
  onNavigateTab?: (tab: string) => void;
}

export function FooterModal({ type, onClose, onNavigateTab }: FooterModalProps) {
  const overlayRef = useRef<HTMLDivElement>(null);
  const modalRef = useRef<HTMLDivElement>(null);
  const [copiedId, setCopiedId] = React.useState<string | null>(null);

  const copyText = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  useEffect(() => {
    if (!type) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        handleClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);

    if (overlayRef.current && modalRef.current) {
      gsap.fromTo(
        overlayRef.current,
        { opacity: 0 },
        { opacity: 1, duration: 0.2, ease: "power2.out" }
      );
      gsap.fromTo(
        modalRef.current,
        { opacity: 0, scale: 0.95, y: 15 },
        { opacity: 1, scale: 1, y: 0, duration: 0.26, ease: "back.out(1.4)" }
      );
    }

    return () => {
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [type]);

  const handleClose = () => {
    if (overlayRef.current && modalRef.current) {
      gsap.to(overlayRef.current, { opacity: 0, duration: 0.15 });
      gsap.to(modalRef.current, {
        opacity: 0,
        scale: 0.96,
        y: 10,
        duration: 0.15,
        onComplete: onClose,
      });
    } else {
      onClose();
    }
  };

  if (!type) return null;

  return (
    <div
      ref={overlayRef}
      id="footer-floating-overlay"
      onClick={(e) => {
        if (e.target === overlayRef.current) handleClose();
      }}
      className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4 sm:p-6 overflow-y-auto"
    >
      <div
        ref={modalRef}
        id="footer-floating-window"
        className="bg-zinc-900 border border-zinc-700/80 rounded-2xl shadow-2xl w-full max-w-2xl max-h-[90vh] flex flex-col overflow-hidden text-zinc-100 relative"
      >
        {/* Header */}
        <div className="px-6 py-4 border-b border-zinc-800 flex items-center justify-between bg-zinc-950/60 sticky top-0 z-10">
          <div className="flex items-center gap-3">
            {type === "how_it_works" && (
              <div className="p-2 rounded-xl bg-teal-500/10 border border-teal-500/30 text-teal-400">
                <Sparkles className="w-5 h-5" />
              </div>
            )}
            {type === "api_docs" && (
              <div className="p-2 rounded-xl bg-indigo-500/10 border border-indigo-500/30 text-indigo-400">
                <BookOpen className="w-5 h-5" />
              </div>
            )}
            {type === "security_lab" && (
              <div className="p-2 rounded-xl bg-purple-500/10 border border-purple-500/30 text-purple-400">
                <Lock className="w-5 h-5" />
              </div>
            )}
            {type === "source_code" && (
              <div className="p-2 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-400">
                <Download className="w-5 h-5" />
              </div>
            )}
            {type === "zero_pii" && (
              <div className="p-2 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                <ShieldCheck className="w-5 h-5" />
              </div>
            )}
            {type === "creator_profile" && (
              <div className="p-2 rounded-xl bg-blue-500/10 border border-blue-500/30 text-blue-400">
                <User className="w-5 h-5" />
              </div>
            )}
            {type === "public_testing_guide" && (
              <div className="p-2 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                <Zap className="w-5 h-5" />
              </div>
            )}

            <div>
              <h2 className="text-base font-bold text-zinc-100 flex items-center gap-2">
                {type === "how_it_works" && "How Aegis Works"}
                {type === "api_docs" && "REST API & OpenAPI Specification"}
                {type === "security_lab" && "Security & Cryptography Lab"}
                {type === "source_code" && "Full-Stack Source Code & Downloads"}
                {type === "zero_pii" && "Zero-PII Cryptographic Guarantee"}
                {type === "creator_profile" && "Creator & Project Information"}
                {type === "public_testing_guide" && "Public Testing & Verification Guide"}
              </h2>
              <p className="text-xs text-zinc-400">
                {type === "how_it_works" && "3-Phase Privacy-Preserving verification workflow"}
                {type === "api_docs" && "Interactive endpoints and live cURL snippets"}
                {type === "security_lab" && "SIMD Blake3, Zeroize, and Canary Dead-Man switch"}
                {type === "source_code" && "Next.js App Router + Native Rust Axum engine"}
                {type === "zero_pii" && "Mathematical proof that raw PII never touches the database"}
                {type === "creator_profile" && "Engineered by Rony M. (ronderins)"}
                {type === "public_testing_guide" && "Immediate steps for testing across web and terminal"}
              </p>
            </div>
          </div>

          <button
            onClick={handleClose}
            className="p-1.5 rounded-lg text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800 transition cursor-pointer"
            aria-label="Close dialog"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 space-y-6 overflow-y-auto text-sm leading-relaxed text-zinc-300">
          {/* HOW IT WORKS MODAL */}
          {type === "how_it_works" && (
            <div className="space-y-4">
              <p className="text-xs text-zinc-300">
                <strong className="text-emerald-400">Aegis</strong> enables individuals to prove they meet eligibility criteria (such as being 18+ or possessing a valid document) without revealing their real name, birthdate, or ID document.
              </p>

              <div className="space-y-3">
                <div className="p-3.5 rounded-xl bg-zinc-950 border border-zinc-800 space-y-1">
                  <span className="text-xs font-mono text-teal-400 font-semibold">1. Client-Side Document Hashing</span>
                  <p className="text-xs text-zinc-400">
                    Your document is hashed directly in your browser using SHA-256 or Blake3. The raw file never leaves your device.
                  </p>
                </div>

                <div className="p-3.5 rounded-xl bg-zinc-950 border border-zinc-800 space-y-1">
                  <span className="text-xs font-mono text-emerald-400 font-semibold">2. Privacy-Preserving Proof Evaluation</span>
                  <p className="text-xs text-zinc-400">
                    The Rust engine computes a non-reversible cryptographic commitment <code className="text-emerald-300 font-mono text-[11px]">Blake3(user_digest || doc_hash || nonce)</code> and verifies the threshold condition (<code className="text-emerald-300 font-mono text-[11px]">age ≥ 18</code>) in ephemeral zeroized memory.
                  </p>
                </div>

                <div className="p-3.5 rounded-xl bg-zinc-950 border border-zinc-800 space-y-1">
                  <span className="text-xs font-mono text-purple-400 font-semibold">3. Cryptographic Token & Merkle Block Ledger</span>
                  <p className="text-xs text-zinc-400">
                    A tamper-evident signed JWT token is issued, and a cryptographic block receipt is committed to an append-only in-memory Merkle chain.
                  </p>
                </div>
              </div>

              <div className="pt-2 flex justify-end gap-2">
                <button
                  onClick={() => {
                    handleClose();
                    onNavigateTab?.("explainer");
                  }}
                  className="px-4 py-2 rounded-lg bg-teal-600 hover:bg-teal-500 text-white text-xs font-semibold flex items-center gap-2 transition"
                >
                  <Sparkles className="w-4 h-4" />
                  <span>Open Full Interactive Explainer Tab</span>
                </button>
              </div>
            </div>
          )}

          {/* API DOCS MODAL */}
          {type === "api_docs" && (
            <div className="space-y-4">
              <div className="p-3.5 bg-emerald-950/30 border border-emerald-800/40 rounded-xl space-y-1.5 text-xs">
                <div className="flex items-center gap-2 font-bold text-emerald-400">
                  <ShieldCheck className="w-4 h-4" />
                  <span>100% Self-Sovereign API Keys (No Sign-Up Required)</span>
                </div>
                <p className="text-zinc-300 text-[11px] leading-relaxed">
                  Keys are fully self-generated and customized by you (e.g. <code className="text-emerald-300 font-mono">openssl rand -hex 32</code>). There are zero vendor registrations, paid third-party accounts, or external approval queues.
                </p>
              </div>

              <p className="text-xs text-zinc-300">
                All endpoints support both <code className="text-indigo-300 font-mono text-[11px]">X-API-Key: &lt;key&gt;</code> and standard <code className="text-indigo-300 font-mono text-[11px]">Authorization: Bearer &lt;key&gt;</code> headers.
              </p>

              <div className="space-y-2 text-xs font-mono">
                <div className="p-3 bg-zinc-950 border border-zinc-800 rounded-lg flex items-center justify-between">
                  <span className="text-emerald-400">POST /api/v1/verify</span>
                  <span className="text-zinc-500 text-[11px]">Mint Privacy-Preserving commitment & proof</span>
                </div>
                <div className="p-3 bg-zinc-950 border border-zinc-800 rounded-lg flex items-center justify-between">
                  <span className="text-teal-400">POST /api/v1/verify-token</span>
                  <span className="text-zinc-500 text-[11px]">Verify signed JWT token</span>
                </div>
                <div className="p-3 bg-zinc-950 border border-zinc-800 rounded-lg flex items-center justify-between">
                  <span className="text-cyan-400">POST /api/v1/verify-merkle</span>
                  <span className="text-zinc-500 text-[11px]">Verify Merkle inclusion path</span>
                </div>
                <div className="p-3 bg-zinc-950 border border-zinc-800 rounded-lg flex items-center justify-between">
                  <span className="text-blue-400">GET /api/v1/proofs/:id</span>
                  <span className="text-zinc-500 text-[11px]">Inspect proof & audit logs</span>
                </div>
                <div className="p-3 bg-zinc-950 border border-zinc-800 rounded-lg flex items-center justify-between">
                  <span className="text-amber-400">GET /api/v1/session</span>
                  <span className="text-zinc-500 text-[11px]">One-time blind QR challenge</span>
                </div>
                <div className="p-3 bg-zinc-950 border border-zinc-800 rounded-lg flex items-center justify-between">
                  <span className="text-purple-400">GET /api/v1/ledger</span>
                  <span className="text-zinc-500 text-[11px]">Query Merkle receipt ledger</span>
                </div>
                <div className="p-3 bg-zinc-950 border border-zinc-800 rounded-lg flex items-center justify-between">
                  <span className="text-teal-400">GET /api/v1/metrics</span>
                  <span className="text-zinc-500 text-[11px]">Microsecond execution telemetry</span>
                </div>
              </div>

              <div className="pt-2 flex justify-end gap-2">
                <button
                  onClick={() => {
                    handleClose();
                    onNavigateTab?.("docs");
                  }}
                  className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold flex items-center gap-2 transition"
                >
                  <BookOpen className="w-4 h-4" />
                  <span>Open Full API Docs Tab</span>
                </button>
              </div>
            </div>
          )}

          {/* SECURITY LAB MODAL */}
          {type === "security_lab" && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                <div className="p-3.5 bg-zinc-950 border border-zinc-800 rounded-xl space-y-1.5">
                  <div className="flex items-center gap-2 text-purple-400 font-semibold">
                    <Cpu className="w-4 h-4" />
                    <span>SIMD-Accelerated Blake3</span>
                  </div>
                  <p className="text-zinc-400 text-[11px]">
                    Sub-microsecond hashing leveraging AVX-512/AVX2 SIMD instructions on x86_64 and NEON on ARM64 without heap allocation.
                  </p>
                </div>

                <div className="p-3.5 bg-zinc-950 border border-zinc-800 rounded-xl space-y-1.5">
                  <div className="flex items-center gap-2 text-emerald-400 font-semibold">
                    <Lock className="w-4 h-4" />
                    <span>Ephemeral Memory Zeroize</span>
                  </div>
                  <p className="text-zinc-400 text-[11px]">
                    All witness secrets implement <code className="text-emerald-300 font-mono">ZeroizeOnDrop</code> to guarantee immediate RAM overwriting.
                  </p>
                </div>

                <div className="p-3.5 bg-zinc-950 border border-zinc-800 rounded-xl space-y-1.5">
                  <div className="flex items-center gap-2 text-amber-400 font-semibold">
                    <ShieldCheck className="w-4 h-4" />
                    <span>Canary Dead-Man Switch</span>
                  </div>
                  <p className="text-zinc-400 text-[11px]">
                    Checks SHA-256 release binary integrity in constant time. Triggers an emergency wipe on detected tampering.
                  </p>
                </div>

                <div className="p-3.5 bg-zinc-950 border border-zinc-800 rounded-xl space-y-1.5">
                  <div className="flex items-center gap-2 text-blue-400 font-semibold">
                    <KeyRound className="w-4 h-4" />
                    <span>Self-Sovereign API Keys</span>
                  </div>
                  <p className="text-zinc-400 text-[11px]">
                    Zero third-party vendor lock-in. Multi-tenant custom keys evaluated with constant-time byte comparisons.
                  </p>
                </div>
              </div>

              <div className="pt-2 flex justify-end gap-2">
                <button
                  onClick={() => {
                    handleClose();
                    onNavigateTab?.("security");
                  }}
                  className="px-4 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold flex items-center gap-2 transition"
                >
                  <Lock className="w-4 h-4" />
                  <span>Open Full Security Lab Tab</span>
                </button>
              </div>
            </div>
          )}

          {/* SOURCE CODE MODAL */}
          {type === "source_code" && (
            <div className="space-y-4">
              <p className="text-xs text-zinc-300">
                The repository is fully self-contained and ready to run. You can download the complete source code or clone the repository directly.
              </p>

              <div className="p-4 bg-zinc-950 border border-zinc-800 rounded-xl space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-zinc-200">Terminal Quick Start</span>
                  <button
                    onClick={() => copyText("git clone https://github.com/ronderins/zk-auth.git\ncd zk-auth\nnpm install\nnpm run dev", "git-clone")}
                    className="p-1 rounded bg-zinc-800 hover:bg-zinc-700 text-[10px] text-zinc-300 font-mono flex items-center gap-1"
                  >
                    {copiedId === "git-clone" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedId === "git-clone" ? "Copied" : "Copy"}</span>
                  </button>
                </div>
                <pre className="p-3 bg-zinc-900 rounded-lg text-emerald-300 font-mono text-xs overflow-x-auto border border-zinc-800">
{`npm install
npm run dev

# Or run Rust engine in parallel:
cd rust-api && cargo run --release`}
                </pre>
              </div>

              <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2">
                <a
                  href="/zk-identity-fullstack.zip"
                  download="zk-identity-fullstack.zip"
                  className="w-full sm:w-auto px-4 py-2 rounded-lg bg-amber-500 hover:bg-amber-400 text-zinc-950 font-bold text-xs flex items-center justify-center gap-2 transition shadow-md"
                >
                  <Download className="w-4 h-4" />
                  <span>Download zk-identity-fullstack.zip</span>
                </a>

                <a
                  href="https://github.com/ronderins"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="w-full sm:w-auto px-4 py-2 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-semibold flex items-center justify-center gap-2 transition border border-zinc-700"
                >
                  <Globe className="w-4 h-4 text-emerald-400" />
                  <span>GitHub Repository</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>
            </div>
          )}

          {/* ZERO PII GUARANTEE MODAL */}
          {type === "zero_pii" && (
            <div className="space-y-4">
              <div className="p-4 bg-emerald-950/30 border border-emerald-800/50 rounded-xl space-y-2">
                <span className="text-xs font-semibold text-emerald-400 flex items-center gap-1.5">
                  <ShieldCheck className="w-4 h-4" /> Privacy Invariant Mathematical Proof
                </span>
                <p className="text-xs text-zinc-300 leading-relaxed">
                  The system enforces a strict Privacy-Preserving architecture. No personal identifiers (names, dates of birth, social security numbers, or biometric files) are ever persisted to disk or SQLite storage tables.
                </p>
              </div>

              <div className="space-y-2 text-xs">
                <div className="p-3 bg-zinc-950 border border-zinc-800 rounded-lg flex items-center justify-between">
                  <span className="text-zinc-400">Stored Database Fields</span>
                  <span className="font-mono text-emerald-400">commitment_hash, criteria_met, token_sig, timestamp</span>
                </div>
                <div className="p-3 bg-zinc-950 border border-zinc-800 rounded-lg flex items-center justify-between">
                  <span className="text-zinc-400">Omitted Personal Fields</span>
                  <span className="font-mono text-red-400">name, birthdate, raw_id, file_scan</span>
                </div>
                <div className="p-3 bg-zinc-950 border border-zinc-800 rounded-lg flex items-center justify-between">
                  <span className="text-zinc-400">Storage Lifetime</span>
                  <span className="font-mono text-teal-400">In-Memory SQLx Pool (Zero-Disk Footprint)</span>
                </div>
              </div>
            </div>
          )}

          {/* CREATOR PROFILE & DYNAMIC DATE MODAL */}
          {type === "creator_profile" && (
            <div className="space-y-4">
              <div className="p-4 bg-zinc-950 border border-zinc-800 rounded-xl flex items-center gap-4">
                <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-emerald-500 to-teal-700 flex items-center justify-center text-zinc-950 font-bold text-lg shadow-lg">
                  RM
                </div>
                <div>
                  <h3 className="text-base font-bold text-zinc-100">
                    <a
                      href="https://github.com/ronderins"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="hover:text-emerald-400 transition underline underline-offset-2"
                    >
                      Rony M.
                    </a>
                  </h3>
                  <a
                    href="https://github.com/ronderins"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs text-emerald-400 font-mono hover:underline inline-block"
                  >
                    @ronderins
                  </a>
                  <p className="text-xs text-zinc-400 mt-0.5">Software Architect & Cryptography Engineer</p>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                <div className="p-3 bg-zinc-950 border border-zinc-800 rounded-lg space-y-1">
                  <span className="text-zinc-500 flex items-center gap-1.5">
                    <Calendar className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Project Release Timestamp</span>
                  </span>
                  <span className="font-mono text-zinc-200 font-semibold">
                    {new Date().toLocaleDateString("en-US", {
                      year: "numeric",
                      month: "long",
                      day: "numeric",
                    })}
                  </span>
                </div>

                <div className="p-3 bg-zinc-950 border border-zinc-800 rounded-lg space-y-1">
                  <span className="text-zinc-500 flex items-center gap-1.5">
                    <Globe className="w-3.5 h-3.5 text-blue-400" />
                    <span>Open-Source License</span>
                  </span>
                  <span className="font-mono text-zinc-200 font-semibold">MIT License (100% Free)</span>
                </div>
              </div>

              <div className="pt-2 flex justify-end gap-2">
                <a
                  href="https://github.com/ronderins"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-2 transition"
                >
                  <Globe className="w-4 h-4" />
                  <span>Visit Rony M. on GitHub (@ronderins)</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>
            </div>
          )}

          {/* PUBLIC TESTING GUIDE MODAL */}
          {type === "public_testing_guide" && (
            <div className="space-y-4">
              <div className="p-3.5 bg-indigo-950/30 border border-indigo-500/40 rounded-xl space-y-1.5 text-xs">
                <span className="font-semibold text-indigo-300 flex items-center gap-1.5">
                  <ShieldCheck className="w-4 h-4 text-indigo-400" /> Why a Dedicated Developer Workbench?
                </span>
                <p className="text-zinc-300 text-[11px] leading-relaxed">
                  Privacy-preserving identity verification is notoriously abstract. If you publish a pure headless Rust backend, 90% of developers, evaluators, and auditors will not clone and run cURL scripts to inspect Merkle roots or zeroize latency. Having a focused UI dramatically increases adoption, comprehension, and trust—provided it stays strictly aligned with developer/security inspection rather than bloated consumer UX.
                </p>
              </div>

              <div className="space-y-3 text-xs">
                <div className="p-3 bg-zinc-950 border border-zinc-800 rounded-lg space-y-1">
                  <span className="font-semibold text-emerald-400 flex items-center gap-1.5">
                    <Zap className="w-3.5 h-3.5" /> 1. Test in the Web UI
                  </span>
                  <p className="text-zinc-400">
                    Switch to the <strong>Interactive Playground</strong> tab, select an age (e.g. 24), choose a threshold (e.g. 18), and click <strong>Generate Verification Proof</strong> to mint a live cryptographic commitment.
                  </p>
                </div>

                <div className="p-3 bg-zinc-950 border border-zinc-800 rounded-lg space-y-1">
                  <span className="font-semibold text-blue-400 flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5" /> 2. Test via cURL Terminal
                  </span>
                  <p className="text-zinc-400">
                    Send a test payload to <code className="text-blue-300 font-mono">/api/v1/verify</code> or inspect the Merkle chain at <code className="text-blue-300 font-mono">/api/v1/ledger</code>.
                  </p>
                </div>
              </div>

              <div className="pt-2 flex justify-end">
                <button
                  onClick={() => {
                    handleClose();
                    onNavigateTab?.("playground");
                  }}
                  className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-2 transition"
                >
                  <Zap className="w-4 h-4" />
                  <span>Go to Interactive Playground</span>
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
