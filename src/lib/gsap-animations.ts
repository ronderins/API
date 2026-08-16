import gsap from "gsap";

/**
 * GSAP smooth animation utilities for navigation, tabs, view transitions, and micro-interactions.
 */

export const animateViewTransition = (
  container: HTMLElement | null,
  onComplete?: () => void
) => {
  if (!container) return;

  // Kill any running animations on container
  gsap.killTweensOf(container);
  gsap.killTweensOf(container.querySelectorAll(".gsap-reveal"));

  const tl = gsap.timeline({
    defaults: { ease: "power3.out" },
    onComplete,
  });

  tl.fromTo(
    container,
    {
      opacity: 0,
      y: 16,
      scale: 0.995,
    },
    {
      opacity: 1,
      y: 0,
      scale: 1,
      duration: 0.4,
      clearProps: "transform",
    }
  );

  const revealElements = container.querySelectorAll(".gsap-reveal");
  if (revealElements.length > 0) {
    tl.fromTo(
      revealElements,
      {
        opacity: 0,
        y: 12,
      },
      {
        opacity: 1,
        y: 0,
        stagger: 0.04,
        duration: 0.35,
        clearProps: "transform",
      },
      "-=0.25"
    );
  }

  return tl;
};

export const animateNavPill = (
  pillElement: HTMLElement | null,
  targetTabElement: HTMLElement | null
) => {
  if (!pillElement || !targetTabElement) return;

  const targetRect = targetTabElement.getBoundingClientRect();
  const parentRect = targetTabElement.parentElement?.getBoundingClientRect() || {
    left: 0,
  };

  const xOffset = targetRect.left - parentRect.left + (targetTabElement.parentElement?.scrollLeft || 0);
  const width = targetRect.width;

  gsap.to(pillElement, {
    x: xOffset,
    width: width,
    duration: 0.35,
    ease: "power3.out",
  });
};

export const animateHoverButton = (el: HTMLElement | null, isEnter: boolean) => {
  if (!el) return;
  gsap.to(el, {
    scale: isEnter ? 1.025 : 1,
    duration: 0.22,
    ease: isEnter ? "back.out(2)" : "power2.out",
  });
};

export const animateHeaderEntrance = (
  headerEl: HTMLElement | null,
  navEl: HTMLElement | null,
  personaEl: HTMLElement | null
) => {
  const tl = gsap.timeline({ defaults: { ease: "power3.out" } });

  if (headerEl) {
    tl.fromTo(
      headerEl,
      { y: -25, opacity: 0 },
      { y: 0, opacity: 1, duration: 0.45 }
    );
  }

  if (personaEl) {
    tl.fromTo(
      personaEl,
      { y: -10, opacity: 0 },
      { y: 0, opacity: 1, duration: 0.35 },
      "-=0.2"
    );
  }

  if (navEl) {
    tl.fromTo(
      navEl.children,
      { y: 12, opacity: 0, scale: 0.96 },
      { y: 0, opacity: 1, scale: 1, stagger: 0.035, duration: 0.4 },
      "-=0.15"
    );
  }

  return tl;
};

/**
 * Animated cryptographic character scramble ticker
 */
export const animateCryptoStream = (
  targetEl: HTMLElement | null,
  finalText: string,
  duration = 0.6
) => {
  if (!targetEl) return;
  const chars = "0123456789abcdefABCDEF";
  const length = finalText.length;
  let frame = 0;
  const totalFrames = Math.floor(duration * 60);

  const interval = setInterval(() => {
    frame++;
    const progress = frame / totalFrames;
    const resolvedCount = Math.floor(progress * length);

    let output = finalText.slice(0, resolvedCount);
    for (let i = resolvedCount; i < length; i++) {
      output += chars[Math.floor(Math.random() * chars.length)];
    }
    targetEl.innerText = output;

    if (frame >= totalFrames) {
      clearInterval(interval);
      targetEl.innerText = finalText;
    }
  }, 16);
};

/**
 * Animated metric number counter
 */
export const animateMetricCounter = (
  targetEl: HTMLElement | null,
  startVal: number,
  endVal: number,
  duration = 0.8,
  suffix = ""
) => {
  if (!targetEl) return;
  const obj = { val: startVal };
  gsap.to(obj, {
    val: endVal,
    duration,
    ease: "power2.out",
    onUpdate: () => {
      targetEl.innerText = `${Math.round(obj.val).toLocaleString()}${suffix}`;
    },
  });
};

/**
 * Glowing pulse wave on verification success
 */
export const animateVerificationSuccess = (container: HTMLElement | null) => {
  if (!container) return;
  gsap.fromTo(
    container,
    { scale: 0.97, borderColor: "rgba(16, 185, 129, 0.9)", boxShadow: "0 0 35px rgba(16, 185, 129, 0.4)" },
    { scale: 1, borderColor: "rgba(16, 185, 129, 0.4)", boxShadow: "0 0 0px rgba(16, 185, 129, 0)", duration: 0.6, ease: "back.out(1.5)" }
  );
};
