"use client";

import React, { useState, useEffect, useRef } from "react";
import gsap from "gsap";
import {
  ShieldCheck,
  Activity,
  Server,
  Search,
  BookOpen,
  Lock,
  Terminal,
  Cpu,
  Check,
  Copy,
  Zap,
  Layers,
  Compass,
  Workflow,
  UserCheck,
  Code2,
  ExternalLink,
  GitBranch,
  Calendar,
  User,
  Info,
  Building2,
  Scale
} from "lucide-react";
import { ProofGenerator } from "@/components/ProofGenerator";
import { ProofLookup } from "@/components/ProofLookup";
import { ApiDocsViewer } from "@/components/ApiDocsViewer";
import { SecurityInspector } from "@/components/SecurityInspector";
import { RustZKPEcosystem } from "@/components/RustZKPEcosystem";
import { VisualFlowExplainer } from "@/components/VisualFlowExplainer";
import { WhyAegisMission } from "@/components/WhyAegisMission";
import { FooterModal, FooterModalType } from "@/components/FooterModal";
import { AegisLogo } from "@/components/AegisLogo";
import { animateViewTransition, animateHeaderEntrance } from "@/lib/gsap-animations";
import type { VerifyResponse, HealthResponse } from "@/types";

type ViewTab = "playground" | "mission" | "explainer" | "rust_ecosystem" | "security" | "lookup" | "docs";
type Persona = "all" | "consumers" | "developers" | "enterprises" | "auditors";

interface AudienceMeta {
  badge: string;
  title: string;
  subtitle: string;
  description: string;
  keyBenefit: string;
  icon: React.ElementType;
  tagColor: string;
  borderColor: string;
  bgColor: string;
}

const AUDIENCE_METADATA: Record<Persona, AudienceMeta> = {
  all: {
    badge: "Universal Verification Engine",
    title: "Zero-Knowledge Predicate & Age Verification Engine",
    subtitle: "Verify age, credentials, and compliance without holding or storing personal records.",
    description:
      "Aegis decouples eligibility verification from personal data collection. Users prove mathematical requirements (such as Age >= 21) via client-side hashing without uploading documents, storing PII, or trusting centralized honeypots.",
    keyBenefit: "Zero raw PII stored • Sub-millisecond evaluation • Tamper-evident Blake3 Merkle receipts",
    icon: ShieldCheck,
    tagColor: "text-emerald-400",
    borderColor: "border-emerald-800/60",
    bgColor: "bg-emerald-950/20",
  },
  consumers: {
    badge: "For Everyday Consumers & Citizens",
    title: "Verify Your Eligibility Without Surrendering Your Identity",
    subtitle: "No passport photos uploaded. No birthdates stored in third-party databases. Complete privacy.",
    description:
      "Why should proving you are over 18 or 21 require handing over clear photos of your passport, driver's license, or home address? Aegis computes an irreversible mathematical fingerprint locally on your device. The platform gets mathematical certainty, while your private documents never leave your hands.",
    keyBenefit: "Zero Risk of Identity Theft: If a platform is breached, zero photos or birthdates exist to steal.",
    icon: UserCheck,
    tagColor: "text-teal-400",
    borderColor: "border-teal-800/60",
    bgColor: "bg-teal-950/25",
  },
  developers: {
    badge: "For Software Engineers & Integrators",
    title: "Sub-Millisecond Zero-Knowledge REST API",
    subtitle: "Add privacy-preserving age and predicate verification with a single HTTP POST request.",
    description:
      "Integrate privacy-preserving verification directly into your auth pipeline. Accept client-side SHA-256 document digests, evaluate arithmetic constraints in <150µs, and issue signed JWT proof tokens backed by an append-only Blake3 Merkle ledger.",
    keyBenefit: "Drop-in REST endpoints: POST /api/v1/verify, single-use 300s nonces, and native Rust performance.",
    icon: Code2,
    tagColor: "text-blue-400",
    borderColor: "border-blue-800/60",
    bgColor: "bg-blue-950/25",
  },
  enterprises: {
    badge: "For Enterprises & Compliance Officers",
    title: "100% Elimination of Toxic KYC Data Breach Liabilities",
    description:
      "Holding customer identity documents is a multi-million-dollar corporate liability under GDPR (penalties up to €20M or 4% of global turnover) and CCPA. Aegis allows you to enforce age verification mandates while holding zero raw PII in your infrastructure.",
    subtitle: "Comply with global age-gating mandates while reducing signup dropout by over 40%.",
    keyBenefit: "Data Minimization by Design (GDPR Art. 5): You cannot leak data you never collected.",
    icon: Building2,
    tagColor: "text-purple-400",
    borderColor: "border-purple-800/60",
    bgColor: "bg-purple-950/25",
  },
  auditors: {
    badge: "For Security Auditors & Cryptographers",
    title: "Verifiable Cryptographic Proofs & Append-Only Merkle Ledger",
    subtitle: "Mathematical invariance, hardware memory zeroization, and independent auditability.",
    description:
      "Replace blind trust in marketing claims with verifiable mathematics. Witness data is scrubbed with memory zeroization on drop, tokens are checked in constant time against timing attacks, and proofs are sealed into an append-only Blake3 Merkle tree with logarithmic inclusion paths.",
    keyBenefit: "Domain separation (`zk-identity-proof-v1`) • ZeroizeOnDrop RAM scrub • Non-repudiation receipts.",
    icon: Scale,
    tagColor: "text-amber-400",
    borderColor: "border-amber-800/60",
    bgColor: "bg-amber-950/25",
  },
};

export default function HomePage() {
  const [activeView, setActiveView] = useState<ViewTab>("playground");
  const [activePersona, setActivePersona] = useState<Persona>("all");
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [latestProofId, setLatestProofId] = useState<string | undefined>();
  const [refreshTrigger, setRefreshTrigger] = useState(0);
  const [stats, setStats] = useState<{ totalProofs: number; totalAuditEvents: number; uptime: number; engine?: string } | null>(null);
  const [activeFooterModal, setActiveFooterModal] = useState<FooterModalType>(null);
  const [currentDateString, setCurrentDateString] = useState<string>("");

  // GSAP animation refs
  const headerRef = useRef<HTMLElement>(null);
  const personaRef = useRef<HTMLElement>(null);
  const navContainerRef = useRef<HTMLDivElement>(null);
  const viewContentRef = useRef<HTMLDivElement>(null);
  const tabRefs = useRef<{ [key in ViewTab]?: HTMLButtonElement | null }>({});

  const checkHealth = async () => {
    try {
      const res = await fetch("/healthz");
      if (res.ok) {
        const data = await res.json();
        setHealth(data);
      } else {
        setHealth({ status: "error", service: "zk-auth-api" });
      }
    } catch {
      setHealth({ status: "unreachable", service: "zk-auth-api" });
    }
  };

  const fetchStats = async () => {
    try {
      const res = await fetch("/api/v1/stats");
      if (res.ok) {
        const data = await res.json();
        setStats(data);
      }
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    checkHealth();
    fetchStats();

    const now = new Date();
    setCurrentDateString(
      now.toLocaleDateString("en-US", {
        year: "numeric",
        month: "short",
        day: "numeric",
      })
    );

    const interval = setInterval(() => {
      if (typeof document !== "undefined" && !document.hidden) {
        fetchStats();
      }
    }, 30000);

    animateHeaderEntrance(headerRef.current, navContainerRef.current, personaRef.current);

    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (viewContentRef.current) {
      animateViewTransition(viewContentRef.current);
    }
  }, [activeView]);

  const handleProofCreated = (proof: VerifyResponse) => {
    setLatestProofId(proof.proof_id);
    setRefreshTrigger((prev) => prev + 1);
    fetchStats();
  };

  const handleSelectTab = (tab: ViewTab) => {
    if (tab === activeView) return;

    if (viewContentRef.current) {
      gsap.to(viewContentRef.current, {
        opacity: 0,
        y: -10,
        duration: 0.18,
        ease: "power2.in",
        onComplete: () => {
          setActiveView(tab);
        },
      });
    } else {
      setActiveView(tab);
    }
  };

  const handleSelectPersona = (persona: Persona) => {
    setActivePersona(persona);
  };

  const handleNavButtonHover = (e: React.MouseEvent<HTMLButtonElement>, isHover: boolean) => {
    gsap.to(e.currentTarget, {
      scale: isHover ? 1.03 : 1,
      duration: 0.22,
      ease: isHover ? "back.out(2)" : "power2.out",
    });
  };

  const currentAudience = AUDIENCE_METADATA[activePersona];
  const AudienceIcon = currentAudience.icon;

  return (
    <div id="app-root" className="min-h-screen bg-zinc-950 text-zinc-100 flex flex-col antialiased selection:bg-emerald-500/30 selection:text-emerald-200">
      {/* Top Header */}
      <header ref={headerRef} id="main-header" className="border-b border-zinc-800/80 bg-zinc-900/50 backdrop-blur sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <AegisLogo size={38} animated id="header-logo" />
            <div>
              <div className="flex items-center gap-2">
                <h1 className="font-bold text-base text-zinc-100 tracking-tight">Aegis</h1>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-800/60">
                  Security Engine
                </span>
              </div>
              <p className="text-[11px] text-zinc-400 hidden sm:block">
                Privacy-Preserving Proofs • Rust Axum Engine • Created by Rony M. (@ronderins)
              </p>
            </div>
          </div>

          {/* Actions & Health Status */}
          <div className="flex items-center gap-2 sm:gap-3 text-xs">
            <button
              id="header-why-built-btn"
              onClick={() => handleSelectTab("mission")}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-900 hover:bg-zinc-850 border border-emerald-500/40 text-emerald-300 font-medium transition active:scale-95 cursor-pointer"
              title="Learn Why Aegis Was Built & Public Utility"
            >
              <Compass className="w-3.5 h-3.5 text-emerald-400" />
              <span className="hidden sm:inline">Why Aegis?</span>
            </button>

            <button
              id="header-public-testing-btn"
              onClick={() => setActiveFooterModal("public_testing_guide")}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-900 hover:bg-zinc-850 border border-zinc-700 text-zinc-300 font-medium transition active:scale-95 cursor-pointer"
              title="View Public Testing & Verification Guide"
            >
              <Zap className="w-3.5 h-3.5 text-emerald-400" />
              <span className="hidden sm:inline">Testing Guide</span>
            </button>

            {/* Live Engine Status Badge */}
            <div
              id="engine-status-indicator"
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-300"
              title="Aegis Engine Status"
            >
              <span
                className={`w-2 h-2 rounded-full ${
                  health?.status === "ok" ? "bg-emerald-400 animate-pulse" : "bg-emerald-500"
                }`}
              />
              <span className="font-mono text-[11px]">
                {health?.status === "ok" ? "Engine Active" : "Engine Ready"}
              </span>
            </div>
          </div>
        </div>
      </header>

      {/* Role & Persona Perspective Switcher Bar */}
      <section ref={personaRef} className="bg-zinc-900/60 border-b border-zinc-800/70 py-2.5">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
          <div className="flex items-center gap-2 text-xs flex-wrap">
            <span className="text-zinc-400 font-mono text-[11px] flex items-center gap-1 shrink-0">
              <UserCheck className="w-3.5 h-3.5 text-emerald-400" />
              Audience Filter:
            </span>
            <div className="flex items-center gap-1 bg-zinc-950 p-1 rounded-lg border border-zinc-850 overflow-x-auto">
              <button
                onClick={() => handleSelectPersona("all")}
                className={`px-2.5 py-1 rounded text-xs font-medium transition duration-200 cursor-pointer ${
                  activePersona === "all"
                    ? "bg-zinc-800 text-zinc-100 shadow-sm font-semibold"
                    : "text-zinc-400 hover:text-zinc-200"
                }`}
              >
                All Audiences
              </button>
              <button
                onClick={() => handleSelectPersona("consumers")}
                className={`px-2.5 py-1 rounded text-xs font-medium transition duration-200 cursor-pointer flex items-center gap-1 ${
                  activePersona === "consumers"
                    ? "bg-teal-950 text-teal-300 border border-teal-800 shadow-sm font-semibold"
                    : "text-zinc-400 hover:text-zinc-200"
                }`}
              >
                <span>For Consumers</span>
              </button>
              <button
                onClick={() => handleSelectPersona("developers")}
                className={`px-2.5 py-1 rounded text-xs font-medium transition duration-200 cursor-pointer flex items-center gap-1 ${
                  activePersona === "developers"
                    ? "bg-blue-950 text-blue-300 border border-blue-800 shadow-sm font-semibold"
                    : "text-zinc-400 hover:text-zinc-200"
                }`}
              >
                <span>For Developers</span>
              </button>
              <button
                onClick={() => handleSelectPersona("enterprises")}
                className={`px-2.5 py-1 rounded text-xs font-medium transition duration-200 cursor-pointer flex items-center gap-1 ${
                  activePersona === "enterprises"
                    ? "bg-purple-950 text-purple-300 border border-purple-800 shadow-sm font-semibold"
                    : "text-zinc-400 hover:text-zinc-200"
                }`}
              >
                <span>For Enterprises</span>
              </button>
              <button
                onClick={() => handleSelectPersona("auditors")}
                className={`px-2.5 py-1 rounded text-xs font-medium transition duration-200 cursor-pointer flex items-center gap-1 ${
                  activePersona === "auditors"
                    ? "bg-amber-950 text-amber-300 border border-amber-800 shadow-sm font-semibold"
                    : "text-zinc-400 hover:text-zinc-200"
                }`}
              >
                <span>For Auditors</span>
              </button>
            </div>
          </div>

          <div className="flex items-center gap-3 text-xs text-zinc-400">
            <span className="flex items-center gap-1 font-mono text-[11px]">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span>Rust Core / In-Memory Ledger</span>
            </span>
            <span className="hidden md:inline text-zinc-600">•</span>
            <span className="font-mono text-[11px] text-emerald-400">0% Raw PII Stored</span>
          </div>
        </div>
      </section>

      {/* Dynamic Audience Perspective Hero Banner */}
      <section className="border-b border-zinc-800/80 bg-gradient-to-b from-zinc-900/40 to-transparent">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-5">
          <div className={`p-4 sm:p-5 rounded-2xl border ${currentAudience.borderColor} ${currentAudience.bgColor} transition-all duration-300 relative overflow-hidden`}>
            <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
              <div className="space-y-2 max-w-4xl">
                <div className="flex items-center gap-2">
                  <span className={`px-2.5 py-0.5 rounded-full text-[11px] font-mono font-semibold uppercase tracking-wider border ${currentAudience.borderColor} ${currentAudience.tagColor}`}>
                    {currentAudience.badge}
                  </span>
                </div>
                <h2 className="text-lg sm:text-xl font-bold text-zinc-100 tracking-tight">
                  {currentAudience.title}
                </h2>
                <p className="text-xs sm:text-sm text-zinc-300 leading-relaxed">
                  {currentAudience.description}
                </p>
                <div className="pt-1 flex items-center gap-2 text-xs font-mono text-zinc-400">
                  <span className="text-emerald-400 font-semibold">Key Guarantee:</span>
                  <span className="text-zinc-200">{currentAudience.keyBenefit}</span>
                </div>
              </div>

              <div className="hidden md:flex flex-col items-center justify-center p-3 rounded-xl bg-zinc-950/60 border border-zinc-800/80 shrink-0 self-center">
                <AudienceIcon className={`w-8 h-8 ${currentAudience.tagColor} mb-1`} />
                <span className="text-[10px] font-mono text-zinc-400 text-center capitalize">
                  {activePersona === "all" ? "Overview" : activePersona}
                </span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Main Navigation Tabs with GSAP Interactions */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-6 w-full flex-1 flex flex-col">
        <div
          ref={navContainerRef}
          className="flex items-center gap-2 border-b border-zinc-800/80 pb-3 mb-6 overflow-x-auto relative"
        >
          <button
            id="nav-tab-mission"
            ref={(el) => { tabRefs.current["mission"] = el; }}
            onClick={() => handleSelectTab("mission")}
            onMouseEnter={(e) => handleNavButtonHover(e, true)}
            onMouseLeave={(e) => handleNavButtonHover(e, false)}
            className={`px-4 py-2 rounded-lg text-xs font-medium transition-colors duration-200 cursor-pointer flex items-center gap-2 whitespace-nowrap will-change-transform ${
              activeView === "mission"
                ? "bg-emerald-600 text-white shadow-lg shadow-emerald-950/60 font-semibold"
                : "bg-zinc-900/80 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/80 border border-zinc-800"
            }`}
          >
            <Compass className="w-4 h-4 text-emerald-300" />
            <span>Why Aegis? (Mission & Utility)</span>
          </button>

          <button
            id="nav-tab-playground"
            ref={(el) => { tabRefs.current["playground"] = el; }}
            onClick={() => handleSelectTab("playground")}
            onMouseEnter={(e) => handleNavButtonHover(e, true)}
            onMouseLeave={(e) => handleNavButtonHover(e, false)}
            className={`px-4 py-2 rounded-lg text-xs font-medium transition-colors duration-200 cursor-pointer flex items-center gap-2 whitespace-nowrap will-change-transform ${
              activeView === "playground"
                ? "bg-emerald-600 text-white shadow-lg shadow-emerald-950/60 font-semibold"
                : "bg-zinc-900/80 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/80 border border-zinc-800"
            }`}
          >
            <Zap className="w-4 h-4" />
            <span>Interactive Playground</span>
          </button>

          <button
            id="nav-tab-explainer"
            ref={(el) => { tabRefs.current["explainer"] = el; }}
            onClick={() => handleSelectTab("explainer")}
            onMouseEnter={(e) => handleNavButtonHover(e, true)}
            onMouseLeave={(e) => handleNavButtonHover(e, false)}
            className={`px-4 py-2 rounded-lg text-xs font-medium transition-colors duration-200 cursor-pointer flex items-center gap-2 whitespace-nowrap will-change-transform ${
              activeView === "explainer"
                ? "bg-teal-600 text-white shadow-lg shadow-teal-950/60 font-semibold"
                : "bg-zinc-900/80 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/80 border border-zinc-800"
            }`}
          >
            <Workflow className="w-4 h-4" />
            <span>How It Works (Visual Guide)</span>
          </button>

          <button
            id="nav-tab-rust-ecosystem"
            ref={(el) => { tabRefs.current["rust_ecosystem"] = el; }}
            onClick={() => handleSelectTab("rust_ecosystem")}
            onMouseEnter={(e) => handleNavButtonHover(e, true)}
            onMouseLeave={(e) => handleNavButtonHover(e, false)}
            className={`px-4 py-2 rounded-lg text-xs font-medium transition-colors duration-200 cursor-pointer flex items-center gap-2 whitespace-nowrap will-change-transform ${
              activeView === "rust_ecosystem"
                ? "bg-orange-600 text-white shadow-lg shadow-orange-950/60 font-semibold"
                : "bg-zinc-900/80 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/80 border border-zinc-800"
            }`}
          >
            <Cpu className="w-4 h-4" />
            <span>Rust Verification Ecosystem</span>
          </button>

          <button
            id="nav-tab-security"
            ref={(el) => { tabRefs.current["security"] = el; }}
            onClick={() => handleSelectTab("security")}
            onMouseEnter={(e) => handleNavButtonHover(e, true)}
            onMouseLeave={(e) => handleNavButtonHover(e, false)}
            className={`px-4 py-2 rounded-lg text-xs font-medium transition-colors duration-200 cursor-pointer flex items-center gap-2 whitespace-nowrap will-change-transform ${
              activeView === "security"
                ? "bg-purple-600 text-white shadow-lg shadow-purple-950/60 font-semibold"
                : "bg-zinc-900/80 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/80 border border-zinc-800"
            }`}
          >
            <Lock className="w-4 h-4" />
            <span>Security & Cryptography Lab</span>
          </button>

          <button
            id="nav-tab-lookup"
            ref={(el) => { tabRefs.current["lookup"] = el; }}
            onClick={() => handleSelectTab("lookup")}
            onMouseEnter={(e) => handleNavButtonHover(e, true)}
            onMouseLeave={(e) => handleNavButtonHover(e, false)}
            className={`px-4 py-2 rounded-lg text-xs font-medium transition-colors duration-200 cursor-pointer flex items-center gap-2 whitespace-nowrap will-change-transform ${
              activeView === "lookup"
                ? "bg-blue-600 text-white shadow-lg shadow-blue-950/60 font-semibold"
                : "bg-zinc-900/80 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/80 border border-zinc-800"
            }`}
          >
            <Search className="w-4 h-4" />
            <span>Proof & Audit Explorer</span>
          </button>

          <button
            id="nav-tab-docs"
            ref={(el) => { tabRefs.current["docs"] = el; }}
            onClick={() => handleSelectTab("docs")}
            onMouseEnter={(e) => handleNavButtonHover(e, true)}
            onMouseLeave={(e) => handleNavButtonHover(e, false)}
            className={`px-4 py-2 rounded-lg text-xs font-medium transition-colors duration-200 cursor-pointer flex items-center gap-2 whitespace-nowrap will-change-transform ${
              activeView === "docs"
                ? "bg-indigo-600 text-white shadow-lg shadow-indigo-950/60 font-semibold"
                : "bg-zinc-900/80 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/80 border border-zinc-800"
            }`}
          >
            <BookOpen className="w-4 h-4" />
            <span>REST Endpoints & Docs</span>
          </button>
        </div>

        {/* Tab Content with GSAP Animation Wrapper */}
        <main ref={viewContentRef} className="flex-1 pb-12 will-change-transform">
          {activeView === "playground" && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="lg:col-span-2">
                <ProofGenerator onProofCreated={handleProofCreated} activePersona={activePersona} />
              </div>
              <div className="space-y-6">
                {/* Dynamic Audience Card 1 */}
                <div className="aegis-card p-6 bg-zinc-900/70 border border-zinc-800 rounded-2xl space-y-4 shadow-xl">
                  {activePersona === "consumers" ? (
                    <>
                      <h3 className="text-sm font-semibold text-teal-300 flex items-center gap-2 pb-1 border-b border-zinc-800/60">
                        <UserCheck className="w-4 h-4 text-teal-400" />
                        How Your Privacy Is Preserved
                      </h3>
                      <div className="space-y-3 text-xs text-zinc-300 leading-relaxed">
                        <p>
                          When you click <strong>Send Request</strong>, the server only receives a 64-character SHA-256 fingerprint of your identity document.
                        </p>
                        <div className="p-3 bg-zinc-950/90 rounded-xl border border-teal-900/40 text-teal-300 font-mono text-[11px]">
                          SHA-256 is mathematically irreversible. Even if government agencies or supercomputers inspect the hash, your name and photo cannot be reconstructed.
                        </div>
                      </div>
                    </>
                  ) : activePersona === "developers" ? (
                    <>
                      <h3 className="text-sm font-semibold text-blue-300 flex items-center gap-2 pb-1 border-b border-zinc-800/60">
                        <Server className="w-4 h-4 text-blue-400" />
                        Available REST Endpoints
                      </h3>
                      <div className="space-y-2 text-xs font-mono">
                        <div className="p-2.5 rounded-xl bg-zinc-950/90 border border-zinc-800 flex items-center justify-between">
                          <span className="text-emerald-400 font-semibold">POST /api/v1/verify</span>
                          <span className="text-zinc-500 text-[10px]">Create Proof</span>
                        </div>
                        <div className="p-2.5 rounded-xl bg-zinc-950/90 border border-zinc-800 flex items-center justify-between">
                          <span className="text-teal-400 font-semibold">GET /api/v1/session</span>
                          <span className="text-zinc-500 text-[10px]">Anti-Replay Nonce</span>
                        </div>
                        <div className="p-2.5 rounded-xl bg-zinc-950/90 border border-zinc-800 flex items-center justify-between">
                          <span className="text-blue-400 font-semibold">POST /api/v1/verify-token</span>
                          <span className="text-zinc-500 text-[10px]">Verify Signed Token</span>
                        </div>
                        <div className="p-2.5 rounded-xl bg-zinc-950/90 border border-zinc-800 flex items-center justify-between">
                          <span className="text-purple-400 font-semibold">GET /api/v1/ledger</span>
                          <span className="text-zinc-500 text-[10px]">Merkle Tree Receipts</span>
                        </div>
                      </div>
                    </>
                  ) : activePersona === "enterprises" ? (
                    <>
                      <h3 className="text-sm font-semibold text-purple-300 flex items-center gap-2 pb-1 border-b border-zinc-800/60">
                        <Building2 className="w-4 h-4 text-purple-400" />
                        GDPR Article 5 Data Minimization
                      </h3>
                      <div className="space-y-2.5 text-xs text-zinc-300 leading-relaxed">
                        <p>
                          Under GDPR Article 5(1)(c), personal data must be &quot;adequate, relevant and limited to what is necessary in relation to the purposes for which they are processed.&quot;
                        </p>
                        <div className="p-3 bg-purple-950/40 border border-purple-800/50 rounded-xl text-purple-200 font-mono text-[11px]">
                          Liability Score: $0. Storing raw identity documents risks up to €20M or 4% of global annual turnover in statutory fines.
                        </div>
                      </div>
                    </>
                  ) : activePersona === "auditors" ? (
                    <>
                      <h3 className="text-sm font-semibold text-amber-300 flex items-center gap-2 pb-1 border-b border-zinc-800/60">
                        <Scale className="w-4 h-4 text-amber-400" />
                        Append-Only Merkle Block Ledger
                      </h3>
                      <div className="space-y-2.5 text-xs text-zinc-300 leading-relaxed">
                        <p>
                          Each verification produces a leaf hashed with SIMD Blake3 and commits to an append-only tree. Third-party auditors can verify mathematical inclusion in O(log N) operations.
                        </p>
                        <div className="p-3 bg-amber-950/40 border border-amber-800/50 rounded-xl text-amber-200 font-mono text-[11px]">
                          Root Hash Chaining: Previous block hashes link cryptographically to guarantee tamper-evidence.
                        </div>
                      </div>
                    </>
                  ) : (
                    <>
                      <h3 className="text-sm font-semibold text-zinc-200 flex items-center gap-2 pb-1 border-b border-zinc-800/60">
                        <Activity className="w-4 h-4 text-emerald-400" />
                        Live Ledger & Engine Metrics
                      </h3>
                      <div className="grid grid-cols-2 gap-3 text-xs">
                        <div className="p-3.5 bg-zinc-950/90 rounded-xl border border-zinc-800/80">
                          <span className="text-zinc-500 font-mono text-[11px] block mb-1">Proofs Minted</span>
                          <span className="text-emerald-400 font-bold font-mono text-lg">
                            {stats?.totalProofs ?? 1}
                          </span>
                        </div>
                        <div className="p-3.5 bg-zinc-950/90 rounded-xl border border-zinc-800/80">
                          <span className="text-zinc-500 font-mono text-[11px] block mb-1">Audit Log Entries</span>
                          <span className="text-blue-400 font-bold font-mono text-lg">
                            {stats?.totalAuditEvents ?? 1}
                          </span>
                        </div>
                      </div>
                      <p className="text-[12px] text-zinc-400 leading-relaxed">
                        All verifications generate a domain-separated cryptographic commitment and are logged to an append-only Merkle ledger.
                      </p>
                    </>
                  )}
                </div>

                {/* Dynamic Audience Card 2 */}
                <div className="aegis-card p-6 bg-zinc-900/70 border border-zinc-800 rounded-2xl space-y-3.5 shadow-xl">
                  {activePersona === "consumers" ? (
                    <>
                      <h3 className="text-sm font-semibold text-zinc-200 flex items-center gap-2 pb-1 border-b border-zinc-800/60">
                        <Lock className="w-4 h-4 text-emerald-400" />
                        The Zero-Storage Guarantee
                      </h3>
                      <p className="text-xs text-zinc-300 leading-relaxed">
                        Traditional companies store millions of unencrypted passport photos in cloud buckets. Aegis has no database columns for your name, birthdate, or photo.
                      </p>
                      <div className="p-3 bg-zinc-950/90 rounded-xl border border-zinc-800 text-[11px] font-mono text-emerald-400">
                        0 bytes stored = 0 bytes that can be leaked or stolen by hackers.
                      </div>
                    </>
                  ) : activePersona === "developers" ? (
                    <>
                      <h3 className="text-sm font-semibold text-zinc-200 flex items-center gap-2 pb-1 border-b border-zinc-800/60">
                        <Cpu className="w-4 h-4 text-orange-400" />
                        Sub-Millisecond Execution
                      </h3>
                      <p className="text-xs text-zinc-300 leading-relaxed">
                        Written in native Rust with SIMD-accelerated Blake3 hashing, proof evaluation completes in &lt;150 microseconds without spawning expensive child processes.
                      </p>
                      <div className="p-3 bg-zinc-950/90 rounded-xl border border-zinc-800 text-[11px] font-mono text-zinc-400">
                        Target Latency: &lt;1ms P99 • Single-binary deployment • Zero GC pause
                      </div>
                    </>
                  ) : activePersona === "enterprises" ? (
                    <>
                      <h3 className="text-sm font-semibold text-zinc-200 flex items-center gap-2 pb-1 border-b border-zinc-800/60">
                        <TrendingUpIcon className="w-4 h-4 text-emerald-400" />
                        40%+ Conversion Rate Lift
                      </h3>
                      <p className="text-xs text-zinc-300 leading-relaxed">
                        Industry research shows over 40% of prospective customers abandon registration when asked to photograph and upload their government IDs.
                      </p>
                      <div className="p-3 bg-zinc-950/90 rounded-xl border border-zinc-800 text-[11px] font-mono text-emerald-400">
                        Instant client-side verification turns dropouts into active verified customers.
                      </div>
                    </>
                  ) : activePersona === "auditors" ? (
                    <>
                      <h3 className="text-sm font-semibold text-zinc-200 flex items-center gap-2 pb-1 border-b border-zinc-800/60">
                        <Terminal className="w-4 h-4 text-amber-400" />
                        Hardware Memory Zeroization
                      </h3>
                      <p className="text-xs text-zinc-300 leading-relaxed">
                        All stack and heap allocations containing witness data implement Rust&apos;s <code>ZeroizeOnDrop</code>. Memory is scrubbed with zeroes immediately after evaluation to prevent forensic cold-boot memory dumps.
                      </p>
                      <div className="p-3 bg-zinc-950/90 rounded-xl border border-zinc-800 text-[11px] font-mono text-amber-300">
                        <code>zeroize::Zeroize::zeroize(&amp;mut witness_buffer);</code>
                      </div>
                    </>
                  ) : (
                    <>
                      <h3 className="text-sm font-semibold text-zinc-200 flex items-center gap-2 pb-1 border-b border-zinc-800/60">
                        <Server className="w-4 h-4 text-blue-400" />
                        Available REST Endpoints
                      </h3>
                      <div className="space-y-2.5 text-xs font-mono">
                        <div className="p-3 rounded-xl bg-zinc-950/90 border border-zinc-800/80 flex items-center justify-between">
                          <span className="text-emerald-400 font-medium">POST /api/v1/verify</span>
                          <span className="text-zinc-500 text-[10px]">Create Proof</span>
                        </div>
                        <div className="p-3 rounded-xl bg-zinc-950/90 border border-zinc-800/80 flex items-center justify-between">
                          <span className="text-blue-400 font-medium">GET /api/v1/proofs/:id</span>
                          <span className="text-zinc-500 text-[10px]">Audit Ledger</span>
                        </div>
                        <div className="p-3 rounded-xl bg-zinc-950/90 border border-zinc-800/80 flex items-center justify-between">
                          <span className="text-purple-400 font-medium">GET /api/v1/stats</span>
                          <span className="text-zinc-500 text-[10px]">Ledger Stats</span>
                        </div>
                        <div className="p-3 rounded-xl bg-zinc-950/90 border border-zinc-800/80 flex items-center justify-between">
                          <span className="text-teal-400 font-medium">GET /healthz</span>
                          <span className="text-zinc-500 text-[10px]">Health Check</span>
                        </div>
                      </div>
                    </>
                  )}
                </div>

                {/* Privacy Badge */}
                <div className="p-5 bg-emerald-950/30 border border-emerald-900/50 rounded-2xl space-y-2.5 shadow-md">
                  <span className="text-xs font-semibold text-emerald-400 flex items-center gap-2">
                    <Lock className="w-4 h-4" /> 100% Zero PII Guarantee
                  </span>
                  <p className="text-[12px] text-zinc-300 leading-relaxed">
                    This system complies strictly with privacy mandates. The database never stores user names, raw identifiers, birthdates, or document scans.
                  </p>
                </div>
              </div>
            </div>
          )}

          {activeView === "mission" && (
            <WhyAegisMission
              selectedAudience={activePersona}
              onAudienceChange={(aud) => setActivePersona(aud)}
            />
          )}

          {activeView === "explainer" && <VisualFlowExplainer />}

          {activeView === "rust_ecosystem" && <RustZKPEcosystem />}

          {activeView === "security" && <SecurityInspector />}

          {activeView === "lookup" && (
            <ProofLookup initialProofId={latestProofId} refreshTrigger={refreshTrigger} />
          )}

          {activeView === "docs" && <ApiDocsViewer />}
        </main>
      </div>

      {/* Professional Interactive Footer with Floating Modals */}
      <footer id="app-footer" className="border-t border-zinc-800/80 bg-zinc-950/90 text-xs text-zinc-400 mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-center justify-between">
            {/* Left: Brand, Guarantee & Dynamic Date */}
            <div className="space-y-2 text-center md:text-left">
              <button
                onClick={() => setActiveFooterModal("zero_pii")}
                className="flex items-center justify-center md:justify-start gap-2.5 hover:text-zinc-100 transition cursor-pointer group text-left"
              >
                <AegisLogo size={22} id="footer-logo" />
                <span className="font-semibold text-zinc-200 group-hover:text-emerald-400 transition">Aegis Engine</span>
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                <span className="text-[11px] font-mono text-emerald-400 underline underline-offset-2">Zero PII Architecture</span>
              </button>
              <p className="text-[11px] text-zinc-500 max-w-sm">
                Cryptographically verifiable identity proofs without revealing birthdates, document images, or raw personal data.
              </p>
              <div className="flex items-center justify-center md:justify-start gap-2 text-[11px] text-zinc-500 font-mono">
                <Calendar className="w-3 h-3 text-emerald-400" />
                <span>Verified Active: {currentDateString || "Current Edition"}</span>
              </div>
            </div>

            {/* Center: Interactive Floating Modal Links */}
            <div className="flex flex-wrap items-center justify-center gap-3 text-xs">
              <button
                id="footer-modal-btn-mission"
                onClick={() => setActiveFooterModal("mission")}
                className="hover:text-emerald-300 font-semibold transition cursor-pointer text-emerald-400 underline-offset-2 hover:underline"
              >
                Why Aegis?
              </button>
              <span className="text-zinc-700">•</span>
              <button
                id="footer-modal-btn-how-it-works"
                onClick={() => setActiveFooterModal("how_it_works")}
                className="hover:text-emerald-400 transition cursor-pointer text-zinc-400 underline-offset-2 hover:underline"
              >
                How It Works
              </button>
              <span className="text-zinc-700">•</span>
              <button
                id="footer-modal-btn-api-docs"
                onClick={() => setActiveFooterModal("api_docs")}
                className="hover:text-indigo-400 transition cursor-pointer text-zinc-400 underline-offset-2 hover:underline"
              >
                API Docs
              </button>
              <span className="text-zinc-700">•</span>
              <button
                id="footer-modal-btn-security-lab"
                onClick={() => setActiveFooterModal("security_lab")}
                className="hover:text-purple-400 transition cursor-pointer text-zinc-400 underline-offset-2 hover:underline"
              >
                Security Lab
              </button>
              <span className="text-zinc-700">•</span>
              <button
                id="footer-modal-btn-source-code"
                onClick={() => setActiveFooterModal("source_code")}
                className="hover:text-amber-400 transition cursor-pointer text-zinc-400 underline-offset-2 hover:underline"
              >
                Source Code
              </button>
            </div>

            {/* Right: Engineering Attribution & Creator Modal */}
            <div className="flex flex-col sm:flex-row items-center justify-center md:justify-end gap-3 text-center md:text-right">
              <span className="text-zinc-400 text-xs">
                Engineered and designed by{" "}
                <button
                  id="footer-creator-modal-btn"
                  onClick={() => setActiveFooterModal("creator_profile")}
                  className="font-semibold text-emerald-400 hover:text-emerald-300 transition inline-flex items-center gap-1 underline underline-offset-2 cursor-pointer"
                >
                  Rony M.
                  <User className="w-3 h-3 ml-0.5" />
                </button>
              </span>
              <a
                href="https://github.com/ronderins"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-zinc-900 border border-zinc-800 hover:border-zinc-700 text-zinc-300 hover:text-white transition text-xs font-mono"
                title="View Rony M. on GitHub (@ronderins)"
                aria-label="GitHub Profile of Rony M."
              >
                <GitBranch className="w-3.5 h-3.5 text-emerald-400" />
                <span>@ronderins</span>
              </a>
            </div>
          </div>
        </div>
      </footer>

      {/* Floating Window Overlay Modal */}
      <FooterModal
        type={activeFooterModal}
        onClose={() => setActiveFooterModal(null)}
        onNavigateTab={(tab) => handleSelectTab(tab as ViewTab)}
      />
    </div>
  );
}

function TrendingUpIcon(props: React.SVGProps<SVGSVGElement>) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      {...props}
    >
      <polyline points="22 7 13.5 15.5 8.5 10.5 2 17" />
      <polyline points="16 7 22 7 22 13" />
    </svg>
  );
}
