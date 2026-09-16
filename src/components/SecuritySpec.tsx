"use client";

import React, { useEffect, useRef } from "react";
import { Lock, EyeOff, ShieldCheck, KeyRound, Cpu, Terminal, CheckCircle2 } from "lucide-react";
import { animateCardsStagger } from "../lib/gsap-animations";

export const SecuritySpec: React.FC = () => {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (containerRef.current) {
      animateCardsStagger(containerRef.current, ".spec-card", {
        yOffset: 16,
        staggerDelay: 0.05,
      });
    }
  }, []);

  return (
    <div ref={containerRef} id="security-spec-container" className="aegis-card bg-zinc-900/70 border border-zinc-800 rounded-2xl p-6 sm:p-7 shadow-xl space-y-6">
      <div className="flex items-center gap-3 pb-4 border-b border-zinc-800/80">
        <Lock className="w-8 h-8 text-emerald-400 shrink-0 filter drop-shadow-[0_0_10px_rgba(52,211,153,0.85)]" />
        <div>
          <h2 className="text-lg font-semibold text-zinc-100">Privacy-Preserving Architecture &amp; Security Invariants</h2>
          <p className="text-xs text-zinc-400">Cryptographic isolation, formal invariants, and zero-trust memory security enforced in native Rust</p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
        <div className="spec-card p-5 bg-zinc-950/90 border border-zinc-800/80 rounded-2xl space-y-2.5 shadow-sm">
          <div className="flex items-center gap-2 text-emerald-400 font-semibold text-sm">
            <EyeOff className="w-4 h-4" />
            <span>Zero Raw Identity Retention</span>
          </div>
          <p className="text-zinc-400 leading-relaxed text-[13px]">
            Raw <code className="text-zinc-300 font-mono">user_id</code> strings never reach the database tables or application logs. Only a non-reversible SHA-256 digest is retained.
          </p>
        </div>

        <div className="spec-card p-5 bg-zinc-950/90 border border-zinc-800/80 rounded-2xl space-y-2.5 shadow-sm">
          <div className="flex items-center gap-2 text-blue-400 font-semibold text-sm">
            <ShieldCheck className="w-4 h-4" />
            <span>No Document Uploads</span>
          </div>
          <p className="text-zinc-400 leading-relaxed text-[13px]">
            Raw ID cards, passports, and documents are never transmitted to this server. Only client-computed 64-character SHA-256 digests are accepted.
          </p>
        </div>

        <div className="spec-card p-5 bg-zinc-950/90 border border-zinc-800/80 rounded-2xl space-y-2.5 shadow-sm">
          <div className="flex items-center gap-2 text-purple-400 font-semibold text-sm">
            <KeyRound className="w-4 h-4" />
            <span>Constant-Time Security</span>
          </div>
          <p className="text-zinc-400 leading-relaxed text-[13px]">
            API key verification uses constant-time byte comparisons (<code className="text-zinc-300 font-mono">subtle::ConstantTimeEq</code> / <code className="text-zinc-300 font-mono">crypto.timingSafeEqual</code>) to prevent side-channel timing attacks.
          </p>
        </div>
      </div>

      {/* Rust Security Guarantee Matrix */}
      <div className="spec-card p-5 bg-zinc-950/90 border border-emerald-500/30 rounded-2xl space-y-4 text-xs shadow-lg">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-1 border-b border-zinc-800/60">
          <span className="font-bold text-emerald-400 flex items-center gap-2 font-mono text-sm">
            <Terminal className="w-4 h-4" /> 10x Rust Security Hardening &amp; Cryptographic Invariants Suite
          </span>
          <span className="px-2.5 py-0.5 rounded-full bg-emerald-950/80 border border-emerald-700/60 text-[11px] text-emerald-300 font-mono self-start sm:self-auto">
            #![forbid(unsafe_code)] • 10x Hardened
          </span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 font-mono text-[11px]">
          <div className="p-3.5 rounded-xl bg-zinc-900/90 border border-zinc-800/80 space-y-1.5 transition-all duration-200 hover:border-zinc-700">
            <span className="text-emerald-400 font-bold flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 shrink-0" /> RAII Zeroize &amp; mlock
            </span>
            <span className="text-zinc-400 text-[11px] leading-relaxed block">zeroize::ZeroizeOnDrop + kernel mlock/MADV_DONTDUMP prevents swap and core dumps.</span>
          </div>
          <div className="p-3.5 rounded-xl bg-zinc-900/90 border border-zinc-800/80 space-y-1.5 transition-all duration-200 hover:border-zinc-700">
            <span className="text-blue-400 font-bold flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 shrink-0" /> Hardware Enclave (TEE)
            </span>
            <span className="text-zinc-400 text-[11px] leading-relaxed block">Intel SGX DCAP / AMD SEV-SNP remote attestation quote validation &amp; MRENCLAVE checks.</span>
          </div>
          <div className="p-3.5 rounded-xl bg-zinc-900/90 border border-zinc-800/80 space-y-1.5 transition-all duration-200 hover:border-zinc-700">
            <span className="text-purple-400 font-bold flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 shrink-0" /> Post-Quantum ML-KEM
            </span>
            <span className="text-zinc-400 text-[11px] leading-relaxed block">Dual-hybrid X25519 + NIST FIPS 203 (ML-KEM-768) lattice encapsulation &amp; ML-DSA.</span>
          </div>
          <div className="p-3.5 rounded-xl bg-zinc-900/90 border border-zinc-800/80 space-y-1.5 transition-all duration-200 hover:border-zinc-700">
            <span className="text-cyan-400 font-bold flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 shrink-0" /> Formal SMT Invariants
            </span>
            <span className="text-zinc-400 text-[11px] leading-relaxed block">Kani model-checked arithmetic overflow-freedom and mathematical ZK soundness theorems.</span>
          </div>
          <div className="p-3.5 rounded-xl bg-zinc-900/90 border border-zinc-800/80 space-y-1.5 transition-all duration-200 hover:border-zinc-700">
            <span className="text-amber-400 font-bold flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 shrink-0" /> Differential Privacy (ε,δ)
            </span>
            <span className="text-zinc-400 text-[11px] leading-relaxed block">Calibrated Laplace &amp; Gaussian mechanisms with strict cumulative privacy budget caps.</span>
          </div>
          <div className="p-3.5 rounded-xl bg-zinc-900/90 border border-zinc-800/80 space-y-1.5 transition-all duration-200 hover:border-zinc-700">
            <span className="text-rose-400 font-bold flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 shrink-0" /> HSM PKCS#11 FIPS 140-3
            </span>
            <span className="text-zinc-400 text-[11px] leading-relaxed block">Level 4 physical tamper-resistant non-exportable hardware key slot isolation &amp; attestation.</span>
          </div>
          <div className="p-3.5 rounded-xl bg-zinc-900/90 border border-zinc-800/80 space-y-1.5 transition-all duration-200 hover:border-zinc-700">
            <span className="text-indigo-400 font-bold flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 shrink-0" /> Seccomp BPF Sandbox
            </span>
            <span className="text-zinc-400 text-[11px] leading-relaxed block">Drops 284 Linux syscalls (disallowing execve, fork, ptrace) to contain zero-day RCEs.</span>
          </div>
          <div className="p-3.5 rounded-xl bg-zinc-900/90 border border-zinc-800/80 space-y-1.5 transition-all duration-200 hover:border-zinc-700">
            <span className="text-teal-400 font-bold flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 shrink-0" /> Timing Shield &amp; Replay
            </span>
            <span className="text-zinc-400 text-[11px] leading-relaxed block">Branchless selection, cache eviction, and Bloom-indexed spent nullifier ledger.</span>
          </div>
        </div>
      </div>

      {/* Autonomous Self-Sovereignty & Zero Vendor Lock-in Banner */}
      <div className="spec-card p-5 bg-gradient-to-r from-emerald-950/40 via-zinc-900/90 to-teal-950/40 border border-emerald-800/40 rounded-2xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 text-xs shadow-md">
        <div className="space-y-1.5">
          <div className="flex items-center gap-2 font-bold text-emerald-400 text-sm">
            <ShieldCheck className="w-4 h-4" />
            <span>100% Self-Sovereign • Zero Third-Party Sign-Ups</span>
          </div>
          <p className="text-zinc-300 text-[12px] leading-relaxed">
            No external cloud accounts, paid vendor tokens, or telemetry beacons exist. Keys are self-generated (e.g. <code className="text-emerald-300 font-mono">openssl rand -hex 32</code>) and fully customized by you.
          </p>
        </div>
        <span className="px-3 py-1 rounded-full bg-emerald-950 border border-emerald-700/60 font-mono text-[11px] text-emerald-300 whitespace-nowrap self-start sm:self-auto">
          Plug &amp; Play Autonomous
        </span>
      </div>

      {/* Developer & Security Inspection Philosophy Banner */}
      <div className="spec-card p-5 bg-zinc-950/90 border border-indigo-500/30 rounded-2xl space-y-3 text-xs shadow-md">
        <div className="flex items-center justify-between pb-1 border-b border-zinc-800/60">
          <span className="font-bold text-indigo-400 flex items-center gap-2 font-mono text-sm">
            <Cpu className="w-4 h-4" /> Why a Focused Developer &amp; Security Workbench UI?
          </span>
          <span className="px-2.5 py-0.5 rounded-full bg-indigo-950 border border-indigo-700/60 text-[11px] text-indigo-300 font-mono">
            Zero-Slop Architectural Rationale
          </span>
        </div>
        <p className="text-zinc-300 text-[12px] leading-relaxed">
          Privacy-preserving identity verification is notoriously abstract. If you publish a pure headless Rust backend, 90% of developers, evaluators, and auditors will not clone and run cURL scripts to inspect Merkle roots or zeroize latency. Having a focused UI dramatically increases adoption, comprehension, and trust—provided it stays strictly aligned with developer/security inspection rather than bloated consumer UX.
        </p>
      </div>

      {/* Cryptographic Domain Separation, Privacy-Preserving Proof Simulation & SQLx In-Memory SQLite */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
        <div className="spec-card p-5 bg-zinc-950/90 border border-zinc-800/80 rounded-2xl space-y-3 shadow-sm">
          <div className="flex items-center gap-2 font-semibold text-zinc-200 text-sm">
            <Cpu className="w-4 h-4 text-emerald-400" />
            <span>Domain-Separated Commitment</span>
          </div>
          <p className="text-zinc-400 text-[12px] leading-relaxed">
            Commitments are calculated deterministically with domain separation and a cryptographic nonce:
          </p>
          <div className="p-3 bg-zinc-900/90 font-mono text-[11px] text-emerald-300 rounded-xl border border-zinc-800/80 break-all select-all">
            SHA-256(&quot;privacy-identity-proof-v1\0&quot; || user_id || 0x00 || doc_hash || 0x00 || age_threshold || 0x00 || nonce)
          </div>
        </div>

        <div className="spec-card p-5 bg-zinc-950/90 border border-zinc-800/80 rounded-2xl space-y-3 shadow-sm">
          <div className="flex items-center gap-2 font-semibold text-zinc-200 text-sm">
            <ShieldCheck className="w-4 h-4 text-blue-400" />
            <span>jwt-simple Signed Token</span>
          </div>
          <p className="text-zinc-400 text-[12px] leading-relaxed">
            Simulates privacy-preserving age threshold validation and generates a tamper-evident HS256 JWT payload token:
          </p>
          <div className="p-3 bg-zinc-900/90 font-mono text-[11px] text-blue-300 rounded-xl border border-zinc-800/80 break-all select-all">
            Claims: &#123; sub: user_id_digest, doc_hash, age_threshold, criteria_met: true, zk_predicate &#125;
          </div>
        </div>

        <div className="spec-card p-5 bg-zinc-950/90 border border-zinc-800/80 rounded-2xl space-y-3 shadow-sm">
          <div className="flex items-center gap-2 font-semibold text-zinc-200 text-sm">
            <Lock className="w-4 h-4 text-purple-400" />
            <span>SQLx SQLite (Zero PII)</span>
          </div>
          <p className="text-zinc-400 text-[12px] leading-relaxed">
            In-memory SQLite database storing verification timestamps, criteria_met, and proof signatures with NO PII:
          </p>
          <div className="p-3 bg-zinc-900/90 font-mono text-[11px] text-purple-300 rounded-xl border border-zinc-800/80 break-all select-all">
            Table: [verification_timestamp, criteria_met, proof_signature, commitment, user_id_digest]
          </div>
        </div>
      </div>
    </div>
  );
};
