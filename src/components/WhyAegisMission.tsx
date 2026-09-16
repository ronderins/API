"use client";

import React, { useState, useRef, useEffect } from "react";
import gsap from "gsap";
import {
  ShieldCheck,
  Lock,
  EyeOff,
  UserCheck,
  Code2,
  Building2,
  Scale,
  Compass,
  Zap,
  CheckCircle2,
  AlertTriangle,
  FileCheck2,
  Server,
  ArrowRight,
  TrendingUp,
  Cpu,
  Globe,
  Database,
  Search,
  DollarSign,
  HeartHandshake,
  Gamepad2,
  Landmark,
  Layers,
  KeyRound
} from "lucide-react";
import { AegisLogo } from "./AegisLogo";
import { animateCardsStagger } from "@/lib/gsap-animations";

type AudienceKey = "all" | "consumers" | "developers" | "enterprises" | "auditors";
type UseCaseKey = "age_gating" | "fintech" | "gaming_social" | "healthcare" | "workplace";

export const WhyAegisMission: React.FC = () => {
  const [activeAudience, setActiveAudience] = useState<AudienceKey>("all");
  const [activeUseCase, setActiveUseCase] = useState<UseCaseKey>("age_gating");
  
  // Interactive Liability & Risk Calculator State
  const [userVolume, setUserVolume] = useState<number>(50000);
  const [breachRiskPercentage, setBreachRiskPercentage] = useState<number>(4.2);

  const containerRef = useRef<HTMLDivElement>(null);
  const cardRef = useRef<HTMLDivElement>(null);
  const useCaseRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (containerRef.current) {
      const cards = containerRef.current.querySelectorAll(".aegis-card");
      animateCardsStagger(Array.from(cards) as HTMLElement[], 0.07);
    }
  }, []);

  useEffect(() => {
    if (cardRef.current) {
      const cards = cardRef.current.querySelectorAll(".aegis-card");
      if (cards.length > 0) {
        animateCardsStagger(Array.from(cards) as HTMLElement[], 0.06);
      }
    }
  }, [activeAudience]);

  useEffect(() => {
    if (useCaseRef.current) {
      gsap.fromTo(
        useCaseRef.current,
        { opacity: 0, x: -10 },
        { opacity: 1, x: 0, duration: 0.28, ease: "power2.out" }
      );
    }
  }, [activeUseCase]);

  // Calculations for traditional KYC liability vs Aegis
  const traditionalPiiRecords = userVolume;
  const traditionalBreachCostUSD = Math.round((userVolume * 165 * (breachRiskPercentage / 100)));
  const aegisPiiStored = 0;
  const aegisBreachLiabilityUSD = 0;
  const estimatedComplianceSavingsUSD = Math.round(userVolume * 1.85);

  const audienceData = {
    consumers: {
      title: "Everyday Consumers & Citizens",
      badge: "Sovereignty & Privacy Protection",
      icon: UserCheck,
      color: "emerald",
      tagline: "Prove your eligibility without handing over your personal life.",
      coreProblem:
        "Every year, hundreds of millions of people upload unredacted photos of their passports, driver's licenses, and birth certificates to random websites just to access age-restricted content or create accounts. When those databases inevitably get hacked, real people suffer identity theft, stalking, and financial fraud.",
      aegisSolution:
        "Aegis enables you to prove you are 18+, 21+, or possess a legitimate credential through mathematical proof. Your actual documents never leave your phone or laptop. The server receives only an irreversible cryptographic fingerprint.",
      benefits: [
        "100% Protection from Data Breaches: Since Aegis never stores your photos, hackers have nothing to steal.",
        "Zero Identity Leaks: Prove your age without revealing your real name, birthdate, or home address.",
        "Device-Side Cryptography: Document hashing happens directly in your browser using WebCrypto.",
        "Portability: Get a cryptographic receipt you can independently verify without relying on a centralized intermediary."
      ],
      quote: "You wouldn't hand your physical birth certificate to every cashier just to prove you are an adult. Why do that on the internet?"
    },
    developers: {
      title: "Software Engineers & Builders",
      badge: "Developer Ergonomics & Speed",
      icon: Code2,
      color: "blue",
      tagline: "Plug-and-play zero-knowledge attestation without cryptographic friction.",
      coreProblem:
        "Building privacy-preserving verification from scratch requires mastering circuit compilation, zero-knowledge constraint systems, trusted setups, and complex algebraic curves. Traditional KYC vendors force developers into proprietary SDKs with expensive subscriptions, cumbersome onboarding, and vendor lock-in.",
      aegisSolution:
        "Aegis provides a high-performance Rust Axum backend with an intuitive REST API (`POST /api/v1/verify`), OpenAPI 3.1 specification, instant responses (<150µs in native Rust), and self-sovereign API keys with zero registration requirements.",
      benefits: [
        "Self-Sovereign API Keys: Generate your own keys (`openssl rand -hex 32`) with no sign-up or credit card.",
        "Sub-Millisecond Engine: SIMD-accelerated Blake3 and SHA-256 commitments for ultra-low latency.",
        "Production-Grade OpenAPI 3.1: Fully typed TypeScript SDK, cURL, Python, Rust, and Solidity calldata examples.",
        "Open-Source Full Stack: Download the complete Next.js and Rust codebase with zero lock-in."
      ],
      quote: "Add verifiable, privacy-preserving checks to your application in under 5 minutes with a standard HTTP call."
    },
    enterprises: {
      title: "Businesses, Platforms & Compliance",
      badge: "Zero Liability & 100% Compliance",
      icon: Building2,
      color: "purple",
      tagline: "Eliminate toxic PII liabilities and boost user onboarding conversions.",
      coreProblem:
        "Holding customer identity documents is a multi-million-dollar corporate liability. Under GDPR (fines up to €20M or 4% of global turnover) and CCPA, a single security breach can bankrupt a company. Furthermore, 40%+ of users abandon signups when asked to upload physical ID cards.",
      aegisSolution:
        "By enforcing a 'Zero PII Retention by Design' architecture, Aegis stores only domain-separated cryptographic commitments and Merkle receipts. If an attacker gains full database access, they obtain 0% usable customer PII.",
      benefits: [
        "Eliminate GDPR & CCPA Data Liability: You cannot leak data you never collected or stored.",
        "Boost User Conversion Rates: Remove customer hesitation by offering privacy-first verification.",
        "Drastic Infrastructure Cost Reductions: Eliminate expensive secure PII cold-storage compliance vaults.",
        "Instant Verification Receipts: Tamper-evident signed JWT tokens with mathematical non-repudiation."
      ],
      quote: "The safest customer database is the one with zero stored personal records."
    },
    auditors: {
      title: "Security Researchers & Regulators",
      badge: "Mathematical Invariance & Auditability",
      icon: Scale,
      color: "amber",
      tagline: "Verifiable mathematical truth replacing blind institutional trust.",
      coreProblem:
        "Traditional identity platforms make opaque marketing claims about 'military-grade encryption' while secretly storing unencrypted customer logs, selling telemetry, or vulnerable to memory scraping attacks.",
      aegisSolution:
        "Aegis provides transparent, verifiable mathematical invariance. It leverages SIMD Blake3 domain separation (`zk-identity-proof-v1`), memory zeroization (`zeroize` crate in Rust), and append-only SQLite Merkle ledgers with cryptographic receipts.",
      benefits: [
        "Formal Domain Separation: Prevents cross-context replaying and cross-protocol forgery.",
        "Hardware-Level Memory Zeroization: RAM is immediately scrubbed upon proof calculation.",
        "Immutable Merkle Ledger: Every verification is committed to a verifiable, hash-linked block chain.",
        "Public Cryptographic Workbench: Verify commitments and inspect raw mathematical steps interactively."
      ],
      quote: "Don't trust marketing promises. Verify the math, the memory zeroization, and the Merkle root."
    }
  };

  const useCases = {
    age_gating: {
      title: "Age-Gated Communities & Digital Content",
      icon: ShieldCheck,
      stakeholders: "Social Networks, Gaming, E-Commerce",
      scenario:
        "Global regulations (such as the UK Online Safety Act, EU Digital Services Act, and US state age-verification laws) mandate verifying whether users are 18+ or 21+. Traditional methods require users to upload ID cards, exposing minors and adults alike to catastrophic breach risks.",
      howAegisSolves:
        "Aegis evaluates the predicate `(current_year - birth_year >= threshold)` client-side and returns a signed cryptographic token. The platform learns `verified: true` without ever knowing the user's date of birth or identity.",
      impact: "100% regulatory compliance with zero collection of sensitive minor/user data."
    },
    fintech: {
      title: "Fintech, Web3 & Accreditations",
      icon: Landmark,
      stakeholders: "DeFi, Neo-Banks, Investment Platforms",
      scenario:
        "Financial platforms need to confirm accredited investor status, OFAC sanctions clearance, or regional eligibility without exposing private financial net worth or storing identity documents on-chain.",
      howAegisSolves:
        "Aegis generates a domain-separated commitment bound to the user's cryptographic wallet or public key. Smart contracts or backend services verify the attestation without on-chain deanonymization.",
      impact: "Auditable compliance without compromising user pseudonymity or Web3 privacy."
    },
    gaming_social: {
      title: "Anti-Bot & Verified Human Status",
      icon: Gamepad2,
      stakeholders: "MMOs, Social Media, Ticketing Platforms",
      scenario:
        "Ticket scalpers, AI bots, and bad actors plague online platforms. Platforms want to ensure that each account represents a unique, verified person without linking accounts to real-world names.",
      howAegisSolves:
        "Aegis generates deterministic, salted nullifiers (`Blake3(user_secret || context_id)`). A user can prove they are unique per platform without revealing their real-world identity.",
      impact: "Effective anti-Sybil protection without building a dystopian surveillance registry."
    },
    healthcare: {
      title: "Health Records & Prescription Verification",
      icon: HeartHandshake,
      stakeholders: "Telehealth, Pharmacies, Insurance",
      scenario:
        "Patients need to prove eligibility for subsidized programs, insurance coverage, or valid prescriptions without broadcasting their entire medical history or medical record numbers across insecure networks.",
      howAegisSolves:
        "Aegis proves predicate criteria (e.g. 'Prescription active and signed by licensed authority') while keeping the specific diagnosis and doctor notes fully encrypted on the patient's device.",
      impact: "Strict HIPAA compliance and total patient medical privacy."
    },
    workplace: {
      title: "Enterprise Access & Security Badging",
      icon: KeyRound,
      stakeholders: "Defense Contractors, Enterprise IT, Cloud Infra",
      scenario:
        "Engineers and contractors need access to high-security servers and physical facilities based on clearance levels without logging their personal IDs in every access server.",
      howAegisSolves:
        "Aegis verifies security clearance cryptographic hashes in RAM with instant memory zeroization, preventing lateral credential theft even if access nodes are compromised.",
      impact: "Zero-trust architecture where access tokens cannot be hijacked or reverse-engineered."
    }
  };

  return (
    <div ref={containerRef} id="why-aegis-mission-container" className="space-y-8">
      {/* Hero Header & Purpose */}
      <div className="bg-gradient-to-br from-zinc-900 via-zinc-900/90 to-emerald-950/30 border border-zinc-800 rounded-2xl p-6 sm:p-8 shadow-2xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-emerald-500/10 rounded-full blur-3xl pointer-events-none -mr-20 -mt-20" />
        
        <div className="relative z-10 space-y-4 max-w-4xl">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/80 border border-emerald-800/60 text-emerald-300 font-mono text-xs">
            <Compass className="w-3.5 h-3.5 text-emerald-400" />
            <span>Mission & Relevance for Every Public</span>
          </div>

          <h2 className="text-2xl sm:text-3xl font-bold text-zinc-100 tracking-tight leading-tight">
            Why Aegis Was Built: Solving the Internet&apos;s Identity Paradox
          </h2>

          <p className="text-sm sm:text-base text-zinc-300 leading-relaxed">
            For decades, the internet has forced a dangerous compromise: to prove eligibility (such as age, citizenship, or credentials), users must upload unredacted passports, driver&apos;s licenses, and private documents. This creates massive honeypots for hackers and exposes billions of people to identity theft.
          </p>

          <p className="text-sm text-zinc-400 leading-relaxed">
            <strong className="text-emerald-400 font-semibold">Aegis replaces blind trust with verifiable mathematics.</strong> Built on high-performance Rust and modern zero-knowledge principles, Aegis enables anyone to prove they meet specific requirements without exposing, transmitting, or storing raw personal data.
          </p>
        </div>
      </div>

      {/* Value Proposition by Audience Selector */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold text-zinc-100 flex items-center gap-2">
              <UserCheck className="w-5 h-5 text-emerald-400" />
              Tailored Value & Relevance for Every Audience
            </h3>
            <p className="text-xs text-zinc-400">
              Select an audience to understand why Aegis is essential for their specific requirements:
            </p>
          </div>

          {/* Selector Tabs */}
          <div className="flex items-center gap-1 bg-zinc-900 p-1.5 rounded-xl border border-zinc-800 overflow-x-auto">
            {(["all", "consumers", "developers", "enterprises", "auditors"] as AudienceKey[]).map((key) => {
              const isActive = activeAudience === key;
              return (
                <button
                  key={key}
                  onClick={() => setActiveAudience(key)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium transition duration-200 capitalize whitespace-nowrap cursor-pointer ${
                    isActive
                      ? "bg-emerald-600 text-white font-semibold shadow-md shadow-emerald-950/60"
                      : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/60"
                  }`}
                >
                  {key === "all" ? "All Publics" : key}
                </button>
              );
            })}
          </div>
        </div>

        {/* Audience Content Matrix */}
        <div ref={cardRef} className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {Object.entries(audienceData).map(([key, data]) => {
            if (activeAudience !== "all" && activeAudience !== key) return null;
            const Icon = data.icon;
            return (
              <div
                key={key}
                className="aegis-card p-6 sm:p-7 bg-zinc-900/60 border border-zinc-800 rounded-2xl flex flex-col justify-between space-y-6 hover:border-zinc-700 transition-all duration-300 shadow-lg hover:shadow-xl hover:shadow-zinc-950/40"
              >
                <div className="space-y-4.5">
                  <div className="flex items-start justify-between gap-3 pb-2 border-b border-zinc-800/60">
                    <div className="flex items-center gap-3.5">
                      <div className="p-2.5 rounded-xl bg-emerald-950/40 border border-emerald-800/40">
                        <Icon className="w-7 h-7 text-emerald-400 shrink-0 filter drop-shadow-[0_0_8px_rgba(52,211,153,0.8)]" />
                      </div>
                      <div>
                        <h4 className="text-base font-bold text-zinc-100">{data.title}</h4>
                        <span className="text-xs font-mono text-emerald-400 block mt-0.5">{data.badge}</span>
                      </div>
                    </div>
                  </div>

                  <p className="text-xs font-medium text-emerald-300 bg-emerald-950/30 border border-emerald-900/50 p-3.5 rounded-xl leading-relaxed">
                    {data.tagline}
                  </p>

                  <div className="space-y-3 text-xs">
                    <div className="p-4 bg-red-950/15 border border-red-900/30 rounded-xl space-y-1.5">
                      <span className="text-red-400 font-semibold flex items-center gap-2">
                        <AlertTriangle className="w-3.5 h-3.5 shrink-0" /> The Broken Status Quo
                      </span>
                      <p className="text-zinc-300 text-xs leading-relaxed">{data.coreProblem}</p>
                    </div>

                    <div className="p-4 bg-zinc-950 border border-zinc-800/90 rounded-xl space-y-1.5">
                      <span className="text-emerald-400 font-semibold flex items-center gap-2">
                        <ShieldCheck className="w-3.5 h-3.5 shrink-0" /> How Aegis Transforms This
                      </span>
                      <p className="text-zinc-300 text-xs leading-relaxed">{data.aegisSolution}</p>
                    </div>
                  </div>

                  <div className="space-y-2.5 pt-1">
                    <span className="text-xs font-mono uppercase tracking-wider text-zinc-400 font-semibold block">
                      Key Practical Benefits
                    </span>
                    <ul className="space-y-2 text-xs text-zinc-300">
                      {data.benefits.map((benefit, i) => (
                        <li key={i} className="flex items-start gap-2.5 leading-relaxed">
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 mt-0.5 shrink-0" />
                          <span>{benefit}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>

                <div className="p-4 bg-zinc-950/70 border border-zinc-850 rounded-xl text-xs text-zinc-400 italic leading-relaxed">
                  &ldquo;{data.quote}&rdquo;
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Real-World Use Cases Deep-Dive */}
      <div className="aegis-card bg-zinc-900/70 border border-zinc-800 rounded-2xl p-6 sm:p-7 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-zinc-800/80">
          <div>
            <h3 className="text-lg font-semibold text-zinc-100 flex items-center gap-2">
              <Layers className="w-5 h-5 text-teal-400" />
              Real-World Applicability &amp; Industry Scenarios
            </h3>
            <p className="text-xs text-zinc-400 mt-0.5">
              See where Aegis is deployed to replace invasive ID verification across industries:
            </p>
          </div>

          <div className="flex items-center gap-2 overflow-x-auto pb-1 sm:pb-0">
            {Object.entries(useCases).map(([k, item]) => {
              const isSelected = activeUseCase === k;
              return (
                <button
                  key={k}
                  onClick={() => setActiveUseCase(k as UseCaseKey)}
                  className={`px-3.5 py-2 rounded-lg text-xs font-medium transition duration-200 cursor-pointer whitespace-nowrap active:scale-95 ${
                    isSelected
                      ? "bg-teal-600 text-white font-semibold shadow-md shadow-teal-950/50"
                      : "bg-zinc-950 text-zinc-400 hover:text-zinc-200 border border-zinc-800 hover:border-zinc-700"
                  }`}
                >
                  {item.title.split(" & ")[0]}
                </button>
              );
            })}
          </div>
        </div>

        {/* Selected Use Case Panel */}
        {(() => {
          const item = useCases[activeUseCase];
          const Icon = item.icon;
          return (
            <div ref={useCaseRef} className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
              <div className="lg:col-span-2 space-y-4">
                <div className="flex items-center gap-3.5 pb-2">
                  <div className="p-2.5 rounded-xl bg-teal-950/40 border border-teal-800/40">
                    <Icon className="w-7 h-7 text-teal-400 shrink-0 filter drop-shadow-[0_0_8px_rgba(45,212,191,0.8)]" />
                  </div>
                  <div>
                    <h4 className="text-base font-bold text-zinc-100">{item.title}</h4>
                    <span className="text-xs text-zinc-400 font-mono">Primary Stakeholders: {item.stakeholders}</span>
                  </div>
                </div>

                <div className="space-y-3.5 text-xs">
                  <div className="p-4 sm:p-4.5 bg-zinc-950/80 rounded-xl border border-zinc-800/80 space-y-2">
                    <span className="text-zinc-400 font-semibold uppercase tracking-wider text-[11px] block font-mono">
                      Industry Challenge
                    </span>
                    <p className="text-zinc-300 leading-relaxed text-xs">{item.scenario}</p>
                  </div>

                  <div className="p-4 sm:p-4.5 bg-teal-950/20 rounded-xl border border-teal-900/40 space-y-2">
                    <span className="text-teal-400 font-semibold uppercase tracking-wider text-[11px] block font-mono">
                      Aegis Cryptographic Resolution
                    </span>
                    <p className="text-zinc-200 leading-relaxed text-xs">{item.howAegisSolves}</p>
                  </div>
                </div>
              </div>

              <div className="p-5 sm:p-6 bg-zinc-950/90 rounded-2xl border border-zinc-800 space-y-4.5">
                <span className="text-xs font-mono font-semibold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
                  <TrendingUp className="w-4 h-4" /> Measurable Outcome
                </span>
                <p className="text-sm font-medium text-zinc-100 leading-relaxed">
                  {item.impact}
                </p>
                <div className="pt-3 border-t border-zinc-850 space-y-2.5 text-xs text-zinc-400">
                  <div className="flex items-center justify-between p-2 rounded-lg bg-zinc-900/50 border border-zinc-850/60">
                    <span>Raw PII Transferred:</span>
                    <span className="font-mono font-bold text-emerald-400">0 Bytes</span>
                  </div>
                  <div className="flex items-center justify-between p-2 rounded-lg bg-zinc-900/50 border border-zinc-855/60">
                    <span>Verification Time:</span>
                    <span className="font-mono font-bold text-blue-400">&lt; 150 µs</span>
                  </div>
                  <div className="flex items-center justify-between p-2 rounded-lg bg-zinc-900/50 border border-zinc-850/60">
                    <span>Audit Trail:</span>
                    <span className="font-mono font-bold text-purple-400">Merkle Chain</span>
                  </div>
                </div>
              </div>
            </div>
          );
        })()}
      </div>

      {/* Interactive Risk & Liability Simulator for Enterprise & Devs */}
      <div className="aegis-card bg-zinc-900/70 border border-zinc-800 rounded-2xl p-6 sm:p-7 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-zinc-800/80">
          <div>
            <h3 className="text-lg font-semibold text-zinc-100 flex items-center gap-2">
              <DollarSign className="w-5 h-5 text-emerald-400" />
              Interactive Compliance &amp; Breach Liability Simulator
            </h3>
            <p className="text-xs text-zinc-400 mt-0.5">
              Simulate the financial and risk impact of traditional PII collection vs Aegis Zero-PII architecture:
            </p>
          </div>
          <div className="px-3.5 py-1.5 rounded-full bg-emerald-950 border border-emerald-800/60 text-emerald-400 font-mono text-xs flex items-center gap-2">
            <Lock className="w-3.5 h-3.5" />
            <span>Mathematical Risk Elimination</span>
          </div>
        </div>

        {/* Sliders */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="p-5 bg-zinc-950/80 border border-zinc-800/90 rounded-xl space-y-3.5">
            <div className="flex items-center justify-between text-xs">
              <span className="text-zinc-300 font-medium">Monthly Active Verifications</span>
              <span className="font-mono font-bold text-emerald-400 text-sm">{userVolume.toLocaleString()} users</span>
            </div>
            <input
              type="range"
              min="1000"
              max="500000"
              step="5000"
              value={userVolume}
              onChange={(e) => setUserVolume(Number(e.target.value))}
              className="w-full h-2 bg-zinc-800 rounded-lg appearance-none cursor-pointer accent-emerald-500"
            />
            <div className="flex justify-between text-[11px] text-zinc-500 font-mono">
              <span>1k</span>
              <span>100k</span>
              <span>250k</span>
              <span>500k</span>
            </div>
          </div>

          <div className="p-5 bg-zinc-950/80 border border-zinc-800/90 rounded-xl space-y-3.5">
            <div className="flex items-center justify-between text-xs">
              <span className="text-zinc-300 font-medium">Estimated Industry Breach Exposure Risk</span>
              <span className="font-mono font-bold text-amber-400 text-sm">{breachRiskPercentage}% / year</span>
            </div>
            <input
              type="range"
              min="1"
              max="15"
              step="0.2"
              value={breachRiskPercentage}
              onChange={(e) => setBreachRiskPercentage(Number(e.target.value))}
              className="w-full h-2 bg-zinc-800 rounded-lg appearance-none cursor-pointer accent-amber-500"
            />
            <div className="flex justify-between text-[11px] text-zinc-500 font-mono">
              <span>1% (Low)</span>
              <span>4.2% (Average)</span>
              <span>15% (High Threat)</span>
            </div>
          </div>
        </div>

        {/* Comparison Metrics */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-1">
          {/* Traditional KYC Box */}
          <div className="p-5 sm:p-6 bg-red-950/20 border border-red-900/40 rounded-2xl space-y-4">
            <div className="flex items-center justify-between pb-2 border-b border-red-950/80">
              <span className="text-sm font-bold text-red-400 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4" /> Traditional KYC (Raw Document Retention)
              </span>
              <span className="text-[10px] font-mono px-2.5 py-0.5 rounded bg-red-950 border border-red-800 text-red-300 font-semibold">
                Extreme Liability
              </span>
            </div>
            <div className="space-y-3.5 text-xs">
              <div className="flex justify-between items-center pb-2.5 border-b border-red-950/60">
                <span className="text-zinc-400">Stored Raw ID Scans &amp; Birthdates:</span>
                <span className="font-mono font-bold text-red-400">{traditionalPiiRecords.toLocaleString()} documents</span>
              </div>
              <div className="flex justify-between items-center pb-2.5 border-b border-red-950/60">
                <span className="text-zinc-400">Potential Breach Liability (IBM Ponemon):</span>
                <span className="font-mono font-bold text-red-400">${traditionalBreachCostUSD.toLocaleString()}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-zinc-400">GDPR / CCPA Regulatory Risk:</span>
                <span className="font-mono font-bold text-red-400">High (Up to 4% Global Turnover)</span>
              </div>
            </div>
          </div>

          {/* Aegis Box */}
          <div className="p-5 sm:p-6 bg-emerald-950/25 border border-emerald-900/50 rounded-2xl space-y-4">
            <div className="flex items-center justify-between pb-2 border-b border-emerald-950/80">
              <span className="text-sm font-bold text-emerald-400 flex items-center gap-2">
                <ShieldCheck className="w-4 h-4" /> Aegis Architecture (Zero PII Guarantee)
              </span>
              <span className="text-[10px] font-mono px-2.5 py-0.5 rounded bg-emerald-950 border border-emerald-800 text-emerald-300 font-semibold">
                Zero Liability
              </span>
            </div>
            <div className="space-y-3.5 text-xs">
              <div className="flex justify-between items-center pb-2.5 border-b border-emerald-950/60">
                <span className="text-zinc-400">Stored Raw ID Scans &amp; Birthdates:</span>
                <span className="font-mono font-bold text-emerald-400">{aegisPiiStored} documents</span>
              </div>
              <div className="flex justify-between items-center pb-2.5 border-b border-emerald-950/60">
                <span className="text-zinc-400">Potential Breach Liability:</span>
                <span className="font-mono font-bold text-emerald-400">${aegisBreachLiabilityUSD} (Zero Usable Data)</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-zinc-400">Estimated Compliance Cost Savings:</span>
                <span className="font-mono font-bold text-emerald-400">${estimatedComplianceSavingsUSD.toLocaleString()} / year</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* The Core Principles / Architectural Manifesto */}
      <div className="aegis-card p-6 sm:p-7 bg-zinc-950 border border-zinc-800 rounded-2xl space-y-5">
        <h4 className="text-xs font-mono uppercase tracking-wider text-emerald-400 font-semibold flex items-center gap-2">
          <Scale className="w-4 h-4" /> The Aegis Architectural Invariants
        </h4>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
          <div className="p-4 bg-zinc-900/80 border border-zinc-800/80 rounded-xl space-y-2">
            <span className="font-bold text-zinc-100 text-sm block">1. Predicates over Raw Data</span>
            <p className="text-zinc-400 text-xs leading-relaxed">
              Applications only ever need answers to questions (&ldquo;Is this person over 18?&rdquo;), never the raw underlying personal secrets (&ldquo;What is their birthday?&rdquo;).
            </p>
          </div>
          <div className="p-4 bg-zinc-900/80 border border-zinc-800/80 rounded-xl space-y-2">
            <span className="font-bold text-zinc-100 text-sm block">2. Self-Sovereignty</span>
            <p className="text-zinc-400 text-xs leading-relaxed">
              No central identity provider should hold a master ledger of who you are, what websites you visit, or when you verify.
            </p>
          </div>
          <div className="p-4 bg-zinc-900/80 border border-zinc-800/80 rounded-xl space-y-2">
            <span className="font-bold text-zinc-100 text-sm block">3. Verifiable Open Science</span>
            <p className="text-zinc-400 text-xs leading-relaxed">
              All cryptographic algorithms, RAM zeroization patterns, and Rust engines are fully open-source and auditable by the global security community.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
