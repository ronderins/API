"use client";

import React, { useState, useRef, useEffect } from "react";
import gsap from "gsap";
import {
  ShieldCheck,
  Lock,
  ArrowRight,
  EyeOff,
  Database,
  CheckCircle2,
  FileText,
  KeyRound,
  Binary,
  Lightbulb,
  Info,
  Play,
  Pause,
  RotateCcw,
  Zap
} from "lucide-react";

export const VisualFlowExplainer: React.FC = () => {
  const [activeStep, setActiveStep] = useState<number>(1);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const cardRef = useRef<HTMLDivElement>(null);
  const progressBarRef = useRef<HTMLDivElement>(null);
  const autoPlayTimerRef = useRef<NodeJS.Timeout | null>(null);

  const steps = [
    {
      id: 1,
      title: "1. Client-Side Document Hashing",
      subtitle: "Your raw ID card never leaves your device",
      icon: FileText,
      color: "emerald",
      badge: "Device Level",
      description:
        "The user's physical ID (passport, driver's license) is hashed locally on their device into a 64-character SHA-256 fingerprint. The actual photo and text are never transmitted across the network.",
      privacyImpact: "100% Client-Side Privacy: No raw document image or text is sent to the server.",
      analogy: "Like presenting a sealed wax seal rather than handing over your original birth certificate.",
      codeSnippet: "client_doc_hash = SHA-256(user_passport_bytes) // 64 hex characters",
    },
    {
      id: 2,
      title: "2. Privacy-Preserving Witness Evaluation",
      subtitle: "Verifying criteria without revealing exact data",
      icon: Binary,
      color: "blue",
      badge: "Cryptographic Circuit",
      description:
        "The system evaluates the mathematical predicate (e.g. 'Age >= 21'). It produces a binary true/false attestation without ever revealing or recording the user's exact date of birth or actual age.",
      privacyImpact: "Privacy-Preserving Proof: The verifier learns only that you meet the requirement, nothing more.",
      analogy: "Like a bouncer with a magic light that shines green if you are over 21, without showing your birthdate.",
      codeSnippet: "predicate = (birth_year <= 2005) -> returns verified: true",
    },
    {
      id: 3,
      title: "3. Salted Cryptographic Commitment",
      subtitle: "Deterministic proof bound with anti-replay nonce",
      icon: KeyRound,
      color: "purple",
      badge: "Domain Separation",
      description:
        "A cryptographic commitment is constructed using SHA-256 with domain separation ('zk-identity-proof-v1'), user digest, document hash, age threshold, and a unique cryptographic nonce.",
      privacyImpact: "Anti-Replay & Tamper-Proof: Replaying an old proof in a different context is mathematically impossible.",
      analogy: "Like stamping the green light with a unique serial number and tamper-evident holographic seal.",
      codeSnippet: "commitment = SHA-256(domain || user_digest || doc_hash || threshold || nonce)",
    },
    {
      id: 4,
      title: "4. Zero-PII Audit Ledger & Signed Token",
      subtitle: "Immutable verification record with zero PII stored",
      icon: Database,
      color: "teal",
      badge: "SQLite / Rust Axum",
      description:
        "The verification event is stored in an in-memory SQLite database. The user receives a cryptographically signed JWT token (`jwt-simple`) that third parties can verify independently.",
      privacyImpact: "Zero PII in Database: Only cryptographic hashes, signatures, and timestamps are stored.",
      analogy: "A notary stamp that anyone can verify is genuine, containing zero personal secrets inside.",
      codeSnippet: "db_record = { verification_timestamp, criteria_met: 'age_over_21', proof_signature }",
    },
  ];

  // GSAP animation whenever step changes
  useEffect(() => {
    if (cardRef.current) {
      gsap.fromTo(
        cardRef.current,
        { opacity: 0, y: 14, scale: 0.99 },
        { opacity: 1, y: 0, scale: 1, duration: 0.35, ease: "power3.out" }
      );
    }
  }, [activeStep]);

  // Handle Autoplay Simulator
  useEffect(() => {
    if (isPlaying) {
      if (progressBarRef.current) {
        gsap.fromTo(
          progressBarRef.current,
          { width: "0%" },
          { width: "100%", duration: 3.5, ease: "none" }
        );
      }
      autoPlayTimerRef.current = setTimeout(() => {
        setActiveStep((prev) => (prev >= 4 ? 1 : prev + 1));
      }, 3500);
    } else {
      if (autoPlayTimerRef.current) clearTimeout(autoPlayTimerRef.current);
      if (progressBarRef.current) gsap.killTweensOf(progressBarRef.current);
    }

    return () => {
      if (autoPlayTimerRef.current) clearTimeout(autoPlayTimerRef.current);
    };
  }, [isPlaying, activeStep]);

  const handleStepClick = (stepId: number) => {
    setIsPlaying(false);
    if (stepId === activeStep) return;
    if (cardRef.current) {
      gsap.to(cardRef.current, {
        opacity: 0,
        y: -8,
        duration: 0.15,
        ease: "power2.in",
        onComplete: () => {
          setActiveStep(stepId);
        },
      });
    } else {
      setActiveStep(stepId);
    }
  };

  return (
    <div id="visual-flow-explainer" className="aegis-card bg-zinc-900/70 border border-zinc-800 rounded-2xl p-6 sm:p-7 shadow-2xl space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-zinc-800/80">
        <div className="flex items-center gap-3.5">
          <div className="p-2.5 rounded-xl bg-emerald-950/40 border border-emerald-800/40">
            <Info className="w-7 h-7 text-emerald-400 shrink-0 filter drop-shadow-[0_0_8px_rgba(52,211,153,0.8)]" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-zinc-100">How Privacy-Preserving Identity Verification Works</h2>
            <p className="text-xs text-zinc-400 mt-0.5">
              Clear, step-by-step interactive explanation of Privacy-Preserving proofs and privacy protection
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2.5">
          <button
            onClick={() => setIsPlaying(!isPlaying)}
            className={`px-3.5 py-2 rounded-xl text-xs font-medium flex items-center gap-2 transition cursor-pointer border active:scale-95 ${
              isPlaying
                ? "bg-emerald-950 text-emerald-300 border-emerald-700 font-semibold"
                : "bg-zinc-900 text-zinc-300 border-zinc-800 hover:text-white hover:border-zinc-700"
            }`}
          >
            {isPlaying ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5 fill-current" />}
            <span>{isPlaying ? "Pause Simulation" : "Auto-Play Walkthrough"}</span>
          </button>
          <div className="flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-emerald-950/80 border border-emerald-800/50 text-emerald-400 font-mono text-xs">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Zero PII Architecture</span>
          </div>
        </div>
      </div>

      {/* Auto-play GSAP progress track */}
      {isPlaying && (
        <div className="h-1.5 w-full bg-zinc-800 rounded-full overflow-hidden">
          <div ref={progressBarRef} className="h-full bg-emerald-500 rounded-full" />
        </div>
      )}

      {/* Step Navigation Pills */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {steps.map((step) => {
          const Icon = step.icon;
          const isSelected = activeStep === step.id;
          return (
            <button
              key={step.id}
              onClick={() => handleStepClick(step.id)}
              onMouseEnter={(e) => gsap.to(e.currentTarget, { scale: 1.02, duration: 0.2, ease: "back.out(2)" })}
              onMouseLeave={(e) => gsap.to(e.currentTarget, { scale: 1, duration: 0.2, ease: "power2.out" })}
              className={`p-3.5 sm:p-4 rounded-xl border text-left transition-all duration-200 flex flex-col gap-1.5 cursor-pointer will-change-transform active:scale-95 ${
                isSelected
                  ? "bg-zinc-850 border-emerald-500/80 text-zinc-100 shadow-lg shadow-emerald-950/40 ring-1 ring-emerald-500/30"
                  : "bg-zinc-950/60 border-zinc-800 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900/80 hover:border-zinc-750"
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono uppercase tracking-wider text-emerald-400 font-bold">
                  Step 0{step.id}
                </span>
                <span className={`w-2 h-2 rounded-full ${isSelected ? "bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.9)]" : "bg-zinc-700"}`} />
              </div>
              <div className="flex items-center gap-2 mt-0.5">
                <Icon className={`w-4 h-4 shrink-0 ${isSelected ? "text-emerald-400" : "text-zinc-500"}`} />
                <span className="text-xs font-semibold truncate text-zinc-200">
                  {step.title.split(". ")[1]}
                </span>
              </div>
            </button>
          );
        })}
      </div>

      {/* Active Step Deep-Dive Card */}
      {(() => {
        const current = steps.find((s) => s.id === activeStep) || steps[0];
        const Icon = current.icon;
        return (
          <div ref={cardRef} className="aegis-card p-6 sm:p-7 bg-zinc-950/90 border border-zinc-800/90 rounded-2xl space-y-5 will-change-transform shadow-xl">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-zinc-850">
              <div className="flex items-center gap-3.5">
                <div className="p-2.5 rounded-xl bg-emerald-950/40 border border-emerald-800/40">
                  <Icon className="w-7 h-7 text-emerald-400 shrink-0 filter drop-shadow-[0_0_8px_rgba(52,211,153,0.8)]" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-zinc-100">{current.title}</h3>
                  <p className="text-xs text-zinc-400 mt-0.5">{current.subtitle}</p>
                </div>
              </div>
              <span className="px-3 py-1 rounded-lg bg-zinc-900 border border-zinc-750 text-zinc-300 font-mono text-xs self-start sm:self-auto">
                {current.badge}
              </span>
            </div>

            <p className="text-sm text-zinc-300 leading-relaxed">
              {current.description}
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-1 text-xs">
              <div className="p-4 sm:p-4.5 bg-emerald-950/20 border border-emerald-900/40 rounded-xl space-y-1.5">
                <span className="text-emerald-400 font-semibold flex items-center gap-2">
                  <EyeOff className="w-4 h-4 shrink-0" /> Privacy &amp; Security Impact
                </span>
                <p className="text-zinc-300 text-xs leading-relaxed">{current.privacyImpact}</p>
              </div>

              <div className="p-4 sm:p-4.5 bg-blue-950/20 border border-blue-900/40 rounded-xl space-y-1.5">
                <span className="text-blue-400 font-semibold flex items-center gap-2">
                  <Lightbulb className="w-4 h-4 shrink-0" /> Real-World Analogy
                </span>
                <p className="text-zinc-300 text-xs leading-relaxed">{current.analogy}</p>
              </div>
            </div>

            <div className="p-4 bg-zinc-900/80 rounded-xl border border-zinc-800 font-mono text-xs text-emerald-300 overflow-x-auto space-y-1.5">
              <span className="text-zinc-500 block text-[10px] uppercase font-bold tracking-wider">
                Under the hood (Rust Engine Operation):
              </span>
              <code className="text-xs text-emerald-300 block">{current.codeSnippet}</code>
            </div>

            {/* Stepper Navigation */}
            <div className="flex items-center justify-between pt-3 border-t border-zinc-850">
              <button
                disabled={activeStep === 1}
                onClick={() => { setIsPlaying(false); setActiveStep((prev) => Math.max(1, prev - 1)); }}
                className="px-4 py-2 text-xs bg-zinc-900 hover:bg-zinc-800 disabled:opacity-40 disabled:hover:bg-zinc-900 rounded-xl border border-zinc-800 text-zinc-300 font-medium transition cursor-pointer active:scale-95"
              >
                Previous Step
              </button>
              <span className="text-xs text-zinc-500 font-mono">
                Step {activeStep} of {steps.length}
              </span>
              <button
                disabled={activeStep === steps.length}
                onClick={() => { setIsPlaying(false); setActiveStep((prev) => Math.min(steps.length, prev + 1)); }}
                className="px-4 py-2 text-xs bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 disabled:hover:bg-emerald-600 text-white rounded-xl font-semibold transition cursor-pointer flex items-center gap-1.5 shadow-md shadow-emerald-950/40 active:scale-95"
              >
                Next Step <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        );
      })()}

      {/* High-Level Comparison */}
      <div className="border-t border-zinc-800/80 pt-6 space-y-4">
        <h4 className="text-xs font-semibold text-zinc-300 uppercase tracking-wider font-mono">
          Architecture Comparison: Traditional vs. Privacy-Preserving
        </h4>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5 text-xs">
          <div className="p-5 sm:p-6 bg-red-950/15 border border-red-900/35 rounded-2xl space-y-3">
            <span className="text-red-400 font-bold text-sm flex items-center gap-2">
              Traditional ID Verification (High Risk)
            </span>
            <ul className="text-zinc-400 space-y-2 leading-relaxed list-disc list-inside">
              <li>Uploads raw passport / driver&apos;s license photos.</li>
              <li>Stores full legal name, date of birth, and home address.</li>
              <li>Massive compliance burden (GDPR, CCPA, HIPAA risk).</li>
              <li>Vulnerable to catastrophic database leaks and identity theft.</li>
            </ul>
          </div>

          <div className="p-5 sm:p-6 bg-emerald-950/20 border border-emerald-900/40 rounded-2xl space-y-3">
            <span className="text-emerald-400 font-bold text-sm flex items-center gap-2">
              Aegis Engine (Zero PII Guarantee)
            </span>
            <ul className="text-zinc-300 space-y-2 leading-relaxed list-disc list-inside">
              <li><strong className="text-emerald-400">Zero uploads</strong>: Only cryptographic SHA-256 digests.</li>
              <li><strong className="text-emerald-400">Zero birthdates stored</strong>: Proofs only assert criteria compliance.</li>
              <li><strong className="text-emerald-400">Mathematically binding</strong>: Tamper-evident JWT tokens &amp; commitments.</li>
              <li><strong className="text-emerald-400">Auditable</strong>: Append-only ledger with cryptographic proofs.</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};
