"use client";

import React, { useState, useEffect, useRef } from "react";
import gsap from "gsap";
import { Search, ShieldAlert, CheckCircle2, Check, History, Database, Lock, ArrowUpRight } from "lucide-react";
import type { ProofResponse, ErrorResponse } from "../types";

interface ProofLookupProps {
  initialProofId?: string;
  refreshTrigger?: number;
}

export const ProofLookup: React.FC<ProofLookupProps> = ({ initialProofId, refreshTrigger }) => {
  const [proofId, setProofId] = useState(initialProofId || "7c6c1d63-6e9e-4e3c-86d4-328e40cc6c04");
  const [loading, setLoading] = useState(false);
  const [proof, setProof] = useState<ProofResponse | null>(null);
  const [error, setError] = useState<ErrorResponse | string | null>(null);
  const [recentList, setRecentList] = useState<ProofResponse[]>([]);
  const resultCardRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (initialProofId) {
      setProofId(initialProofId);
      fetchProofById(initialProofId);
    }
  }, [initialProofId]);

  useEffect(() => {
    if (proof && resultCardRef.current) {
      gsap.fromTo(
        resultCardRef.current,
        { opacity: 0, y: 14, scale: 0.99 },
        { opacity: 1, y: 0, scale: 1, duration: 0.35, ease: "power3.out" }
      );
    }
  }, [proof]);

  const loadRecentProofs = async () => {
    try {
      const res = await fetch("/api/v1/proofs");
      if (res.ok) {
        const data = await res.json();
        setRecentList(data.proofs || []);
      }
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    loadRecentProofs();
  }, [refreshTrigger]);

  const fetchProofById = async (idToFetch: string) => {
    const cleanId = idToFetch.trim();
    if (!cleanId) return;

    setLoading(true);
    setError(null);
    setProof(null);

    try {
      const res = await fetch(`/api/v1/proofs/${cleanId}`);
      const data = await res.json();

      if (!res.ok) {
        setError(data as ErrorResponse);
      } else {
        setProof(data as ProofResponse);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Lookup failed");
    } finally {
      setLoading(false);
    }
  };

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchProofById(proofId);
  };

  return (
    <div id="proof-lookup-container" className="bg-zinc-900/70 border border-zinc-800 rounded-xl p-6 shadow-xl space-y-6">
      <div className="flex items-center justify-between pb-4 border-b border-zinc-800/80">
        <div className="flex items-center gap-3">
          <Search className="w-8 h-8 text-blue-400 shrink-0 filter drop-shadow-[0_0_10px_rgba(96,165,250,0.85)]" />
          <div>
            <h2 className="text-lg font-semibold text-zinc-100">Proof & Audit Trail Query</h2>
            <p className="text-xs text-zinc-400">GET /api/v1/proofs/&#123;id&#125; — Retrieve audit events & commitment hash</p>
          </div>
        </div>
        <span className="px-2.5 py-1 text-xs font-mono font-medium rounded-full bg-blue-950/80 text-blue-400 border border-blue-800/60">
          GET /api/v1/proofs/:id
        </span>
      </div>

      {/* Query Bar */}
      <form onSubmit={handleSearchSubmit} className="flex gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-3.5 top-3 w-4 h-4 text-zinc-500" />
          <input
            id="input-lookup-proof-id"
            type="text"
            value={proofId}
            onChange={(e) => setProofId(e.target.value)}
            placeholder="Enter Proof UUID (e.g. 7c6c1d63-6e9e-4e3c-86d4-328e40cc6c04)"
            required
            className="w-full bg-zinc-950 border border-zinc-700/80 rounded-lg pl-10 pr-3.5 py-2.5 text-sm text-zinc-100 placeholder-zinc-500 focus:outline-none focus:border-blue-500 font-mono transition"
          />
        </div>
        <button
          id="btn-lookup-submit"
          type="submit"
          disabled={loading}
          className="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 disabled:bg-blue-800/50 text-white font-medium text-sm rounded-lg transition cursor-pointer flex items-center gap-2 active:scale-95"
        >
          {loading ? "Searching..." : "Lookup Proof"}
        </button>
      </form>

      {/* Recent Proofs Quick Selector */}
      {recentList.length > 0 && (
        <div>
          <span className="text-xs font-medium text-zinc-400 block mb-2">
            Active Records in In-Memory / SQLite Repository ({recentList.length}):
          </span>
          <div className="flex flex-wrap gap-2">
            {recentList.slice(0, 5).map((p) => (
              <button
                key={p.proof_id}
                type="button"
                onClick={() => {
                  setProofId(p.proof_id);
                  fetchProofById(p.proof_id);
                }}
                onMouseEnter={(e) => gsap.to(e.currentTarget, { scale: 1.04, duration: 0.18, ease: "power2.out" })}
                onMouseLeave={(e) => gsap.to(e.currentTarget, { scale: 1, duration: 0.18, ease: "power2.out" })}
                className={`text-xs font-mono px-2.5 py-1 rounded-md border transition duration-150 flex items-center gap-1.5 cursor-pointer will-change-transform ${
                  proof?.proof_id === p.proof_id
                    ? "bg-blue-950 text-blue-300 border-blue-600 shadow-sm"
                    : "bg-zinc-950 text-zinc-400 border-zinc-800 hover:border-zinc-700"
                }`}
              >
                <span>{p.proof_id.slice(0, 8)}...</span>
                <span className="text-[10px] text-zinc-500">≥{p.age_threshold}yo</span>
                <ArrowUpRight className="w-3 h-3 text-zinc-500" />
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Proof Found Display */}
      {proof && (
        <div ref={resultCardRef} id="proof-result-card" className="space-y-4 pt-2 will-change-transform">
          <div className="p-4 bg-zinc-950 border border-zinc-800 rounded-xl space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                <span className="text-sm font-semibold text-zinc-200">Proof Commitment Record</span>
              </div>
              <span className="px-2 py-0.5 text-xs font-mono rounded bg-emerald-950/60 text-emerald-400 border border-emerald-800/40">
                status: {proof.status}
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              <div className="p-2.5 bg-zinc-900/80 rounded border border-zinc-800/80">
                <span className="text-zinc-500 block font-mono text-[11px] mb-0.5">Proof ID</span>
                <span className="text-zinc-200 font-mono select-all">{proof.proof_id}</span>
              </div>

              <div className="p-2.5 bg-zinc-900/80 rounded border border-zinc-800/80">
                <span className="text-zinc-500 block font-mono text-[11px] mb-0.5">Compliance Criteria Met</span>
                <span className="text-emerald-400 font-mono font-medium flex items-center gap-1.5">
                  <Check className="w-3.5 h-3.5" /> {typeof proof.criteria_met === "string" ? proof.criteria_met : "criteria_met = true"}
                </span>
              </div>

              <div className="p-2.5 bg-zinc-900/80 rounded border border-zinc-800/80">
                <span className="text-zinc-500 block font-mono text-[11px] mb-0.5">Age Threshold</span>
                <span className="text-zinc-200 font-mono font-medium">≥ {proof.age_threshold} years old</span>
              </div>

              <div className="p-2.5 bg-zinc-900/80 rounded border border-zinc-800/80">
                <div className="flex items-center justify-between mb-0.5">
                  <span className="text-zinc-500 font-mono text-[11px]">User ID Digest (SHA-256)</span>
                  <span className="text-[10px] text-emerald-400 flex items-center gap-1"><Lock className="w-2.5 h-2.5" /> Zero PII</span>
                </div>
                <span className="text-zinc-300 font-mono break-all text-[11px] select-all">{proof.user_id_digest}</span>
              </div>

              <div className="p-2.5 bg-zinc-900/80 rounded border border-zinc-800/80">
                <span className="text-zinc-500 block font-mono text-[11px] mb-0.5">Document SHA-256 Hash</span>
                <span className="text-zinc-300 font-mono break-all text-[11px] select-all">{proof.document_hash}</span>
              </div>

              <div className="p-2.5 bg-zinc-900/80 rounded border border-zinc-800/80 md:col-span-2">
                <span className="text-zinc-500 block font-mono text-[11px] mb-0.5">Cryptographic Salted Commitment</span>
                <span className="text-emerald-400 font-mono break-all text-[11px] select-all">{proof.commitment}</span>
              </div>

              {(proof.proof_signature || proof.signed_token) && (
                <div className="p-2.5 bg-zinc-900/80 rounded border border-zinc-800/80 md:col-span-2">
                  <div className="flex items-center justify-between mb-0.5">
                    <span className="text-zinc-500 font-mono text-[11px]">proof_signature (`jwt-simple` HS256 Token)</span>
                    <span className="text-[10px] text-blue-400 font-mono">Rust In-Memory SQLite</span>
                  </div>
                  <span className="text-emerald-300 font-mono break-all text-[11px] select-all block bg-zinc-950 p-2 rounded border border-zinc-850">
                    {proof.proof_signature || proof.signed_token}
                  </span>
                </div>
              )}

              <div className="p-2.5 bg-zinc-900/80 rounded border border-zinc-800/80 md:col-span-2">
                <span className="text-zinc-500 block font-mono text-[11px] mb-0.5">verification_timestamp (SQLite ISO-8601)</span>
                <span className="text-zinc-300 font-mono text-[11px]">{proof.verification_timestamp || proof.created_at}</span>
              </div>
            </div>
          </div>

          {/* Audit Events Trail */}
          <div className="p-4 bg-zinc-950 border border-zinc-800 rounded-xl space-y-3">
            <div className="flex items-center gap-2">
              <History className="w-4 h-4 text-blue-400" />
              <h3 className="text-sm font-semibold text-zinc-200">Append-Only Audit Trail</h3>
              <span className="text-xs text-zinc-500 font-mono">({proof.audit_trail.length} events)</span>
            </div>

            <div className="space-y-2">
              {proof.audit_trail.map((evt) => (
                <div
                  key={evt.event_id}
                  className="p-3 bg-zinc-900/90 border border-zinc-800/80 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono"
                >
                  <div className="flex items-center gap-2">
                    <span className="px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400 text-[10px]">
                      #{evt.event_id}
                    </span>
                    <span className="text-blue-400 font-semibold">{evt.event_type}</span>
                    <span className="text-zinc-500 text-[11px]">
                      meta: {JSON.stringify(evt.metadata)}
                    </span>
                  </div>
                  <span className="text-zinc-500 text-[11px]">{evt.created_at}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Error state */}
      {error && (
        <div id="proof-lookup-error" className="p-4 bg-red-950/30 border border-red-800/50 rounded-xl">
          <div className="flex items-center gap-2 text-red-400 text-xs font-semibold mb-1">
            <ShieldAlert className="w-4 h-4" /> Proof Not Found (404)
          </div>
          <pre className="text-xs text-red-300 font-mono bg-zinc-900 p-3 rounded-lg overflow-x-auto border border-red-900/40">
            {typeof error === "string" ? error : JSON.stringify(error, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
};
