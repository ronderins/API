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
  Sparkles,
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
      icon: Sparkles,
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
    <div id="visual-flow-explainer" className="bg-zinc-900/70 border border-zinc-800 rounded-xl p-6 shadow-xl space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-zinc-800/80">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
            <Info className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-zinc-100">How Privacy-Preserving Identity Verification Works</h2>
            <p className="text-xs text-zinc-400">
              Clear, step-by-step interactive explanation of Privacy-Preserving proofs and privacy protection
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setIsPlaying(!isPlaying)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition cursor-pointer border ${
              isPlaying
                ? "bg-emerald-950 text-emerald-300 border-emerald-700"
                : "bg-zinc-900 text-zinc-300 border-zinc-800 hover:text-white"
            }`}
          >
            {isPlaying ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5 fill-current" />}
            <span>{isPlaying ? "Pause Simulation" : "Auto-Play Walkthrough"}</span>
          </button>
          <div className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-800/50 text-emerald-400 font-mono text-xs">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Zero PII Architecture</span>
          </div>
        </div>
      </div>

      {/* Auto-play GSAP progress track */}
      {isPlaying && (
        <div className="h-1 w-full bg-zinc-800 rounded-full overflow-hidden">
          <div ref={progressBarRef} className="h-full bg-emerald-500 rounded-full" />
        </div>
      )}

      {/* Step Navigation Pills */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
        {steps.map((step) => {
          const Icon = step.icon;
          const isSelected = activeStep === step.id;
          return (
            <button
              key={step.id}
              onClick={() => handleStepClick(step.id)}
              onMouseEnter={(e) => gsap.to(e.currentTarget, { scale: 1.025, duration: 0.2, ease: "back.out(2)" })}
              onMouseLeave={(e) => gsap.to(e.currentTarget, { scale: 1, duration: 0.2, ease: "power2.out" })}
              className={`p-3 rounded-lg border text-left transition duration-200 flex flex-col gap-1 cursor-pointer will-change-transform ${
                isSelected
                  ? "bg-zinc-850 border-emerald-500 text-zinc-100 shadow-md shadow-emerald-950/40"
                  : "bg-zinc-950/60 border-zinc-800 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900"
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono uppercase tracking-wider text-emerald-400 font-semibold">
                  Step 0{step.id}
                </span>
                <span className={`w-2 h-2 rounded-full ${isSelected ? "bg-emerald-400 animate-pulse" : "bg-zinc-700"}`} />
              </div>
              <div className="flex items-center gap-2 mt-1">
                <Icon className={`w-4 h-4 ${isSelected ? "text-emerald-400" : "text-zinc-500"}`} />
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
          <div ref={cardRef} className="p-5 bg-zinc-950/80 border border-zinc-800/90 rounded-xl space-y-4 will-change-transform">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-zinc-850">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
                  <Icon className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-semibold text-zinc-100">{current.title}</h3>
                  <p className="text-xs text-zinc-400">{current.subtitle}</p>
                </div>
              </div>
              <span className="px-2.5 py-1 rounded bg-zinc-900 border border-zinc-750 text-zinc-300 font-mono text-[11px] self-start sm:self-auto">
                {current.badge}
              </span>
            </div>

            <p className="text-sm text-zinc-300 leading-relaxed">
              {current.description}
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 text-xs">
              <div className="p-3 bg-emerald-950/20 border border-emerald-900/40 rounded-lg space-y-1">
                <span className="text-emerald-400 font-semibold flex items-center gap-1.5">
                  <EyeOff className="w-3.5 h-3.5" /> Privacy & Security Impact
                </span>
                <p className="text-zinc-300 text-[11px] leading-normal">{current.privacyImpact}</p>
              </div>

              <div className="p-3 bg-blue-950/20 border border-blue-900/40 rounded-lg space-y-1">
                <span className="text-blue-400 font-semibold flex items-center gap-1.5">
                  <Sparkles className="w-3.5 h-3.5" /> Real-World Analogy
                </span>
                <p className="text-zinc-300 text-[11px] leading-normal">{current.analogy}</p>
              </div>
            </div>

            <div className="p-3 bg-zinc-900 rounded-lg border border-zinc-800 font-mono text-xs text-emerald-300 overflow-x-auto">
              <span className="text-zinc-500 block text-[10px] uppercase mb-1">Under the hood (Rust Engine Operation):</span>
              <code>{current.codeSnippet}</code>
            </div>

            {/* Stepper Navigation */}
            <div className="flex items-center justify-between pt-2">
              <button
                disabled={activeStep === 1}
                onClick={() => { setIsPlaying(false); setActiveStep((prev) => Math.max(1, prev - 1)); }}
                className="px-3 py-1.5 text-xs bg-zinc-900 hover:bg-zinc-800 disabled:opacity-40 disabled:hover:bg-zinc-900 rounded border border-zinc-800 text-zinc-300 font-medium transition cursor-pointer"
              >
                Previous Step
              </button>
              <span className="text-xs text-zinc-500 font-mono">
                Step {activeStep} of {steps.length}
              </span>
              <button
                disabled={activeStep === steps.length}
                onClick={() => { setIsPlaying(false); setActiveStep((prev) => Math.min(steps.length, prev + 1)); }}
                className="px-3 py-1.5 text-xs bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 disabled:hover:bg-emerald-600 text-white rounded font-medium transition cursor-pointer flex items-center gap-1"
              >
                Next Step <ArrowRight className="w-3 h-3" />
              </button>
            </div>
          </div>
        );
      })()}

      {/* High-Level Comparison */}
      <div className="border-t border-zinc-800/80 pt-5 space-y-3">
        <h4 className="text-xs font-semibold text-zinc-300 uppercase tracking-wider font-mono">
          Architecture Comparison: Traditional vs. Privacy-Preserving
        </h4>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-4 bg-red-950/15 border border-red-900/30 rounded-xl space-y-2">
            <span className="text-red-400 font-semibold flex items-center gap-1.5">
              Traditional ID Verification (High Risk)
            </span>
            <ul className="text-zinc-400 space-y-1.5 list-disc list-inside">
              <li>Uploads raw passport / driver&apos;s license photos.</li>
              <li>Stores full legal name, date of birth, and home address.</li>
              <li>Massive compliance burden (GDPR, CCPA, HIPAA risk).</li>
              <li>Vulnerable to catastrophic database leaks and identity theft.</li>
            </ul>
          </div>

          <div className="p-4 bg-emerald-950/20 border border-emerald-900/40 rounded-xl space-y-2">
            <span className="text-emerald-400 font-semibold flex items-center gap-1.5">
              Aegis Engine (Zero PII Guarantee)
            </span>
            <ul className="text-zinc-300 space-y-1.5 list-disc list-inside">
              <li><strong className="text-emerald-400">Zero uploads</strong>: Only cryptographic SHA-256 digests.</li>
              <li><strong className="text-emerald-400">Zero birthdates stored</strong>: Proofs only assert criteria compliance.</li>
              <li><strong className="text-emerald-400">Mathematically binding</strong>: Tamper-evident JWT tokens & commitments.</li>
              <li><strong className="text-emerald-400">Auditable</strong>: Append-only ledger with cryptographic proofs.</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};
