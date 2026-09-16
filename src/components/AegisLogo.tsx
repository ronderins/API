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

        {/* Pure Outline Shield Profile (Zero Background Fill) */}
        <path
          d="M50 8 L84 24 V52 C84 72 68 88 50 94 C32 88 16 72 16 52 V24 L50 8 Z"
          fill="none"
          stroke={`url(#${gradientId})`}
          strokeWidth="3.2"
          strokeLinecap="round"
          strokeLinejoin="round"
          filter={`url(#${glowId})`}
        />

        {/* Dynamic Aegis Interlocking Cryptographic Core (Pure Outline, Zero Background Fill) */}
        {/* Upper Chevron / Keynode */}
        <path
          d="M50 25 L68 37 L50 49 L32 37 Z"
          fill="none"
          stroke="#a7f3d0"
          strokeWidth="2"
          strokeLinejoin="round"
        />

        {/* Lower Prism / Zero-Knowledge Nexus */}
        <path
          d="M50 53 L66 41 V56 C66 67 59 74 50 78 C41 74 34 67 34 56 V41 L50 53 Z"
          fill="none"
          stroke="#34d399"
          strokeWidth="2"
          strokeLinejoin="round"
        />

        {/* Central Core Attestation Node */}
        <circle
          cx="50"
          cy="49"
          r="4.5"
          fill="none"
          stroke="#6ee7b7"
          strokeWidth="2"
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
