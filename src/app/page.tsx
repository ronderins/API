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
  RefreshCw,
  Download,
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
  Info
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

type ViewTab = "playground" | "mission" | "explainer" | "rust_ecosystem" | "security" | "lookup" | "docs" | "download";
type Persona = "all" | "consumers" | "developers" | "enterprises" | "auditors" | "visual_guide" | "interactive_api" | "rust_deep_dive" | "security_audit";

export default function HomePage() {
  const [activeView, setActiveView] = useState<ViewTab>("playground");
  const [activePersona, setActivePersona] = useState<Persona>("all");
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthLoading, setHealthLoading] = useState(false);
  const [latestProofId, setLatestProofId] = useState<string | undefined>();
  const [refreshTrigger, setRefreshTrigger] = useState(0);
  const [stats, setStats] = useState<{ totalProofs: number; totalAuditEvents: number; uptime: number; engine?: string } | null>(null);
  const [copiedSnippet, setCopiedSnippet] = useState<string | null>(null);
  const [activeFooterModal, setActiveFooterModal] = useState<FooterModalType>(null);
  const [currentDateString, setCurrentDateString] = useState<string>("");

  // GSAP animation refs
  const headerRef = useRef<HTMLElement>(null);
  const personaRef = useRef<HTMLElement>(null);
  const navContainerRef = useRef<HTMLDivElement>(null);
  const viewContentRef = useRef<HTMLDivElement>(null);
  const tabRefs = useRef<{ [key in ViewTab]?: HTMLButtonElement | null }>({});

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSnippet(id);
    setTimeout(() => setCopiedSnippet(null), 2000);
  };

  const checkHealth = async () => {
    setHealthLoading(true);
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
    } finally {
      setHealthLoading(false);
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

  // Entrance animations and dynamic date on initial mount
  useEffect(() => {
    checkHealth();
    fetchStats();
    
    // Dynamic localized date formatting
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

  // Butter-smooth GSAP transition on activeView change
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
    if (persona === "visual_guide") {
      handleSelectTab("explainer");
    } else if (persona === "interactive_api") {
      handleSelectTab("playground");
    } else if (persona === "rust_deep_dive") {
      handleSelectTab("rust_ecosystem");
    } else if (persona === "security_audit") {
      handleSelectTab("security");
    } else if (persona === "consumers" || persona === "developers" || persona === "enterprises" || persona === "auditors") {
      handleSelectTab("mission");
    }
  };

  const handleNavButtonHover = (e: React.MouseEvent<HTMLButtonElement>, isHover: boolean) => {
    gsap.to(e.currentTarget, {
      scale: isHover ? 1.03 : 1,
      duration: 0.22,
      ease: isHover ? "back.out(2)" : "power2.out",
    });
  };

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

            <a
              id="header-download-zip-btn"
              href="/zk-identity-fullstack.zip"
              download="zk-identity-fullstack.zip"
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium shadow-md shadow-emerald-950/40 transition active:scale-95"
              title="Download clean root-level zip file"
            >
              <Download className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Download ZIP</span>
            </a>

            <button
              id="btn-health-check"
              onClick={checkHealth}
              disabled={healthLoading}
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-zinc-900 border border-zinc-800 hover:border-zinc-700 text-zinc-300 transition cursor-pointer active:scale-95"
              title="Click to re-check /healthz"
            >
              <span className={`w-2 h-2 rounded-full ${health?.status === "ok" ? "bg-emerald-400 animate-pulse" : "bg-red-400"}`} />
              <span className="font-mono text-[11px] hidden sm:inline">
                {health?.status === "ok" ? "Engine Active" : "Checking..."}
              </span>
              <RefreshCw className={`w-3 h-3 text-zinc-500 ${healthLoading ? "animate-spin" : ""}`} />
            </button>
          </div>
        </div>
      </header>

      {/* Role & Persona Perspective Switcher Bar */}
      <section ref={personaRef} className="bg-zinc-900/60 border-b border-zinc-800/70 py-2.5">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-xs">
            <span className="text-zinc-400 font-mono text-[11px] flex items-center gap-1">
              <UserCheck className="w-3.5 h-3.5 text-emerald-400" />
              Audience Filter:
            </span>
            <div className="flex items-center gap-1 bg-zinc-950 p-1 rounded-lg border border-zinc-850 overflow-x-auto">
              <button
                onClick={() => handleSelectPersona("all")}
                className={`px-2.5 py-1 rounded text-xs font-medium transition duration-200 cursor-pointer ${
                  activePersona === "all" ? "bg-zinc-800 text-zinc-100 shadow-sm" : "text-zinc-400 hover:text-zinc-200"
                }`}
              >
                All Views
              </button>
              <button
                onClick={() => handleSelectPersona("consumers")}
                className={`px-2.5 py-1 rounded text-xs font-medium transition duration-200 cursor-pointer flex items-center gap-1 ${
                  activePersona === "consumers" ? "bg-emerald-950 text-emerald-300 border border-emerald-800 shadow-sm" : "text-zinc-400 hover:text-zinc-200"
                }`}
              >
                <span>For Consumers</span>
              </button>
              <button
                onClick={() => handleSelectPersona("developers")}
                className={`px-2.5 py-1 rounded text-xs font-medium transition duration-200 cursor-pointer flex items-center gap-1 ${
                  activePersona === "developers" ? "bg-blue-950 text-blue-300 border border-blue-800 shadow-sm" : "text-zinc-400 hover:text-zinc-200"
                }`}
              >
                <span>For Developers</span>
              </button>
              <button
                onClick={() => handleSelectPersona("enterprises")}
                className={`px-2.5 py-1 rounded text-xs font-medium transition duration-200 cursor-pointer flex items-center gap-1 ${
                  activePersona === "enterprises" ? "bg-purple-950 text-purple-300 border border-purple-800 shadow-sm" : "text-zinc-400 hover:text-zinc-200"
                }`}
              >
                <span>For Enterprises</span>
              </button>
              <button
                onClick={() => handleSelectPersona("auditors")}
                className={`px-2.5 py-1 rounded text-xs font-medium transition duration-200 cursor-pointer flex items-center gap-1 ${
                  activePersona === "auditors" ? "bg-amber-950 text-amber-300 border border-amber-800 shadow-sm" : "text-zinc-400 hover:text-zinc-200"
                }`}
              >
                <span>For Auditors</span>
              </button>
            </div>
          </div>

          <div className="flex items-center gap-3 text-xs text-zinc-400">
            <span className="flex items-center gap-1 font-mono text-[11px]">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span>Rust Axum / SQLite In-Memory</span>
            </span>
            <span className="hidden md:inline text-zinc-600">•</span>
            <span className="font-mono text-[11px] text-emerald-400">0% Raw PII Stored</span>
          </div>
        </div>
      </section>

      {/* Main Navigation Tabs with GSAP Butter-Smooth Interactions */}
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
            <span>Rust Privacy-Preserving Ecosystem</span>
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

          <button
            id="nav-tab-download"
            ref={(el) => { tabRefs.current["download"] = el; }}
            onClick={() => handleSelectTab("download")}
            onMouseEnter={(e) => handleNavButtonHover(e, true)}
            onMouseLeave={(e) => handleNavButtonHover(e, false)}
            className={`px-4 py-2 rounded-lg text-xs font-medium transition-colors duration-200 cursor-pointer flex items-center gap-2 whitespace-nowrap will-change-transform ${
              activeView === "download"
                ? "bg-amber-600 text-white shadow-lg shadow-amber-950/60 font-semibold"
                : "bg-zinc-900/80 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/80 border border-zinc-800"
            }`}
          >
            <Download className="w-4 h-4" />
            <span>Download Project (ZIP)</span>
          </button>
        </div>

        {/* Tab Content with GSAP Animation Wrapper */}
        <main ref={viewContentRef} className="flex-1 pb-12 will-change-transform">
          {activeView === "playground" && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="lg:col-span-2">
                <ProofGenerator onProofCreated={handleProofCreated} />
              </div>
              <div className="space-y-6">
                {/* Live System Stats */}
                <div className="p-5 bg-zinc-900/70 border border-zinc-800 rounded-xl space-y-4">
                  <h3 className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
                    <Activity className="w-4 h-4 text-emerald-400" />
                    Live Ledger & Engine Metrics
                  </h3>
                  <div className="grid grid-cols-2 gap-3 text-xs">
                    <div className="p-3 bg-zinc-950 rounded-lg border border-zinc-800">
                      <span className="text-zinc-500 font-mono text-[11px] block">Proofs Minted</span>
                      <span className="text-emerald-400 font-bold font-mono text-base">
                        {stats?.totalProofs ?? 1}
                      </span>
                    </div>
                    <div className="p-3 bg-zinc-950 rounded-lg border border-zinc-800">
                      <span className="text-zinc-500 font-mono text-[11px] block">Audit Log Entries</span>
                      <span className="text-blue-400 font-bold font-mono text-base">
                        {stats?.totalAuditEvents ?? 1}
                      </span>
                    </div>
                  </div>
                  <p className="text-[11px] text-zinc-400 leading-relaxed">
                    All verifications generate a domain-separated cryptographic commitment and are logged to an in-memory SQLx SQLite ledger.
                  </p>
                </div>

                {/* Quick Architecture Guide for Devs */}
                <div className="p-5 bg-zinc-900/70 border border-zinc-800 rounded-xl space-y-3">
                  <h3 className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
                    <Server className="w-4 h-4 text-blue-400" />
                    Available REST Endpoints
                  </h3>
                  <div className="space-y-2 text-xs font-mono">
                    <div className="p-2.5 rounded bg-zinc-950 border border-zinc-800 flex items-center justify-between">
                      <span className="text-emerald-400">POST /api/v1/verify</span>
                      <span className="text-zinc-500 text-[10px]">Create Proof</span>
                    </div>
                    <div className="p-2.5 rounded bg-zinc-950 border border-zinc-800 flex items-center justify-between">
                      <span className="text-blue-400">GET /api/v1/proofs/:id</span>
                      <span className="text-zinc-500 text-[10px]">Audit Ledger</span>
                    </div>
                    <div className="p-2.5 rounded bg-zinc-950 border border-zinc-800 flex items-center justify-between">
                      <span className="text-purple-400">GET /api/v1/stats</span>
                      <span className="text-zinc-500 text-[10px]">Ledger Stats</span>
                    </div>
                    <div className="p-2.5 rounded bg-zinc-950 border border-zinc-800 flex items-center justify-between">
                      <span className="text-teal-400">GET /healthz</span>
                      <span className="text-zinc-500 text-[10px]">Health Check</span>
                    </div>
                  </div>
                </div>

                {/* Privacy Badge */}
                <div className="p-4 bg-emerald-950/20 border border-emerald-900/40 rounded-xl space-y-2">
                  <span className="text-xs font-semibold text-emerald-400 flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5" /> 100% Zero PII Guarantee
                  </span>
                  <p className="text-[11px] text-zinc-300 leading-normal">
                    This system complies strictly with privacy mandates. The database never stores user names, raw identifiers, birthdates, or document scans.
                  </p>
                </div>
              </div>
            </div>
          )}

          {activeView === "mission" && <WhyAegisMission />}

          {activeView === "explainer" && <VisualFlowExplainer />}

          {activeView === "rust_ecosystem" && <RustZKPEcosystem />}

          {activeView === "security" && <SecurityInspector />}

          {activeView === "lookup" && (
            <ProofLookup initialProofId={latestProofId} refreshTrigger={refreshTrigger} />
          )}

          {activeView === "docs" && <ApiDocsViewer />}

          {activeView === "download" && (
            <div id="download-panel" className="bg-zinc-900/70 border border-zinc-800 rounded-xl p-6 shadow-xl space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-zinc-800/80">
                <div className="flex items-center gap-3">
                  <Download className="w-8 h-8 text-amber-400 shrink-0 filter drop-shadow-[0_0_10px_rgba(251,191,36,0.85)]" />
                  <div>
                    <h2 className="text-lg font-semibold text-zinc-100">Download Ready-to-Run Full-Stack Project</h2>
                    <p className="text-xs text-zinc-400">Direct `.zip` package with no nested root folder wrapper — extracts directly to Next.js project root</p>
                  </div>
                </div>

                <a
                  id="main-download-button"
                  href="/zk-identity-fullstack.zip"
                  download="zk-identity-fullstack.zip"
                  className="px-5 py-2.5 bg-amber-500 hover:bg-amber-400 text-zinc-950 font-bold text-sm rounded-lg shadow-lg shadow-amber-950/50 flex items-center justify-center gap-2 transition cursor-pointer whitespace-nowrap"
                >
                  <Download className="w-4 h-4" />
                  Download zk-identity-fullstack.zip
                </a>
              </div>

              {/* What's Included */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div className="p-4 bg-zinc-950 border border-zinc-800 rounded-xl space-y-3">
                  <h3 className="font-semibold text-zinc-200 flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-emerald-400" />
                    Option 1: Run Next.js Full-Stack (Default)
                  </h3>
                  <p className="text-zinc-400">
                    Runs the full Next.js App Router application with embedded cryptographic engine and API routes on port 3000.
                  </p>
                  <div className="relative">
                    <pre className="p-3 bg-zinc-900 rounded-lg text-emerald-300 font-mono text-xs border border-zinc-800 overflow-x-auto">
{`# 1. Extract ZIP (extracts directly to root folder)
# 2. Install dependencies & run
npm install
npm run dev`}
                    </pre>
                    <button
                      onClick={() => copyToClipboard("npm install\nnpm run dev", "opt1")}
                      className="absolute top-2 right-2 p-1.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-[10px] flex items-center gap-1 font-mono cursor-pointer"
                    >
                      {copiedSnippet === "opt1" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      {copiedSnippet === "opt1" ? "Copied" : "Copy"}
                    </button>
                  </div>
                </div>

                <div className="p-4 bg-zinc-950 border border-zinc-800 rounded-xl space-y-3">
                  <h3 className="font-semibold text-zinc-200 flex items-center gap-2">
                    <Cpu className="w-4 h-4 text-amber-400" />
                    Option 2: Run Rust Backend + Next.js Frontend
                  </h3>
                  <p className="text-zinc-400">
                    Runs the native high-performance Rust Axum API on port 8080 while Next.js proxies seamlessly to it.
                  </p>
                  <div className="relative">
                    <pre className="p-3 bg-zinc-900 rounded-lg text-amber-300 font-mono text-xs border border-zinc-800 overflow-x-auto">
{`# Terminal 1: Run Rust API
cd rust-api
cargo run --release

# Terminal 2: Run Next.js App
npm run dev`}
                    </pre>
                    <button
                      onClick={() => copyToClipboard("cd rust-api && cargo run --release", "opt2")}
                      className="absolute top-2 right-2 p-1.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-[10px] flex items-center gap-1 font-mono cursor-pointer"
                    >
                      {copiedSnippet === "opt2" ? <Check className="w-3 h-3 text-amber-400" /> : <Copy className="w-3 h-3" />}
                      {copiedSnippet === "opt2" ? "Copied" : "Copy"}
                    </button>
                  </div>
                </div>
              </div>

              {/* Extraction Specs */}
              <div className="p-4 bg-zinc-950/80 border border-zinc-800/80 rounded-xl text-xs space-y-2">
                <div className="flex items-center gap-2 text-zinc-300 font-semibold">
                  <Check className="w-4 h-4 text-emerald-400" />
                  <span>Zip Package Architecture Details</span>
                </div>
                <ul className="text-zinc-400 space-y-1 list-disc list-inside">
                  <li><strong className="text-zinc-200">Zero Nested Root Wrapper:</strong> Extracts directly into the project workspace root.</li>
                  <li><strong className="text-zinc-200">Rust API Folder Included:</strong> Contains Dockerfile, Cargo.toml, error algebraic enums, and comprehensive test suite.</li>
                  <li><strong className="text-zinc-200">Production Ready:</strong> Fully typed TypeScript components and complete OpenAPI documentation.</li>
                </ul>
              </div>
            </div>
          )}
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
