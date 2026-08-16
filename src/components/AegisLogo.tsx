import React from "react";

interface AegisLogoProps {
  size?: "xs" | "sm" | "md" | "lg" | "xl" | number;
  className?: string;
  showWordmark?: boolean;
  subtitle?: string;
  animated?: boolean;
  id?: string;
}

export function AegisLogo({
  size = "md",
  className = "",
  showWordmark = false,
  subtitle,
  animated = false,
  id,
}: AegisLogoProps) {
  let dimension = 36;
  if (typeof size === "number") {
    dimension = size;
  } else {
    switch (size) {
      case "xs":
        dimension = 20;
        break;
      case "sm":
        dimension = 28;
        break;
      case "md":
        dimension = 36;
        break;
      case "lg":
        dimension = 48;
        break;
      case "xl":
        dimension = 64;
        break;
    }
  }

  const gradientId = id ? `aegis-grad-${id}` : "aegis-grad-default";
  const glowId = id ? `aegis-glow-${id}` : "aegis-glow-default";
  const innerGradId = id ? `aegis-inner-${id}` : "aegis-inner-default";

  const mark = (
    <div
      className={`relative flex items-center justify-center select-none ${animated ? "group" : ""} ${className}`}
      style={{ width: dimension, height: dimension }}
    >
      {/* Ambient background glow */}
      <div
        className="absolute inset-0 rounded-2xl bg-emerald-500/20 blur-md transition-all duration-300 group-hover:bg-emerald-400/30"
        style={{ transform: "scale(0.85)" }}
      />

      <svg
        viewBox="0 0 100 100"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="w-full h-full relative z-10 transition-transform duration-300 ease-out group-hover:scale-105"
      >
        <defs>
          {/* Main Shield Gradient: Emerald to Teal & Cyan */}
          <linearGradient id={gradientId} x1="15%" y1="10%" x2="85%" y2="90%">
            <stop offset="0%" stopColor="#34d399" />
            <stop offset="50%" stopColor="#10b981" />
            <stop offset="100%" stopColor="#0d9488" />
          </linearGradient>

          {/* Secondary Facet Gradient: Deep Shadowing */}
          <linearGradient id={`${gradientId}-facet`} x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#064e3b" stopOpacity="0.9" />
            <stop offset="100%" stopColor="#022c22" stopOpacity="0.95" />
          </linearGradient>

          {/* Inner Prism Core Gradient: Cyan to Emerald */}
          <linearGradient id={innerGradId} x1="50%" y1="0%" x2="50%" y2="100%">
            <stop offset="0%" stopColor="#6ee7b7" />
            <stop offset="100%" stopColor="#14b8a6" />
          </linearGradient>

          {/* Glow filter */}
          <filter id={glowId} x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
        </defs>

        {/* Outer Backing Shield Plate */}
        <path
          d="M50 8 L84 24 V52 C84 72 68 88 50 94 C32 88 16 72 16 52 V24 L50 8 Z"
          fill={`url(#${gradientId}-facet)`}
          stroke="#065f46"
          strokeWidth="2.5"
          strokeLinejoin="round"
        />

        {/* Left Protective Wing / Facet */}
        <path
          d="M50 8 L16 24 V52 C16 72 32 88 50 94 V8 Z"
          fill="#047857"
          fillOpacity="0.25"
        />

        {/* Right Protective Wing Highlight */}
        <path
          d="M50 8 L84 24 V52 C84 72 68 88 50 94 V8 Z"
          fill="#10b981"
          fillOpacity="0.1"
        />

        {/* Outer Shield Outline Accent with Gradient */}
        <path
          d="M50 11 L81 25.5 V50 C81 68 67 83 50 89 C33 83 19 68 19 50 V25.5 L50 11 Z"
          stroke={`url(#${gradientId})`}
          strokeWidth="3"
          strokeLinecap="round"
          strokeLinejoin="round"
          filter={`url(#${glowId})`}
        />

        {/* Dynamic Aegis Interlocking Cryptographic Core */}
        {/* Upper Chevron / Keynode */}
        <path
          d="M50 25 L68 37 L50 49 L32 37 Z"
          fill={`url(#${innerGradId})`}
          stroke="#a7f3d0"
          strokeWidth="1.5"
          strokeLinejoin="round"
        />

        {/* Lower Prism / Zero-Knowledge Nexus */}
        <path
          d="M50 53 L66 41 V56 C66 67 59 74 50 78 C41 74 34 67 34 56 V41 L50 53 Z"
          fill={`url(#${gradientId})`}
          stroke="#34d399"
          strokeWidth="1.5"
          strokeLinejoin="round"
        />

        {/* Central Core Attestation Diamond */}
        <circle
          cx="50"
          cy="49"
          r="4.5"
          fill="#ffffff"
          className="animate-pulse"
        />
        <circle
          cx="50"
          cy="49"
          r="2"
          fill="#065f46"
        />
      </svg>
    </div>
  );

  if (!showWordmark) {
    return mark;
  }

  return (
    <div className="flex items-center gap-3">
      {mark}
      <div>
        <div className="flex items-center gap-2">
          <span className="font-bold text-base text-zinc-100 tracking-tight">Aegis</span>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-800/60">
            Security Engine
          </span>
        </div>
        {subtitle && (
          <p className="text-[11px] text-zinc-400 leading-tight mt-0.5">
            {subtitle}
          </p>
        )}
      </div>
    </div>
  );
}
