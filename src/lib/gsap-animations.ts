import gsap from "gsap";

/**
 * Senior Software Engineer animation utilities:
 * Fast, dignified, compositor-friendly transitions (opacity & micro-displacement).
 * Strictly NO elastic rubber-band bounces (`back.out`), NO fuzzy sub-pixel scaling,
 * and sub-200ms latency budgets for crisp UI response.
 */

export const animateViewTransition = (
  container: HTMLElement | null,
  onComplete?: () => void
) => {
  if (!container) return;

  gsap.killTweensOf(container);
  gsap.killTweensOf(container.querySelectorAll(".gsap-reveal"));

  const tl = gsap.timeline({
    defaults: { ease: "power2.out" },
    onComplete,
  });

  tl.fromTo(
    container,
    {
      opacity: 0,
      y: 6,
    },
    {
      opacity: 1,
      y: 0,
      duration: 0.18,
      clearProps: "transform",
    }
  );

  const revealElements = container.querySelectorAll(".gsap-reveal");
  if (revealElements.length > 0) {
    tl.fromTo(
      revealElements,
      {
        opacity: 0,
        y: 4,
      },
      {
        opacity: 1,
        y: 0,
        stagger: 0.02,
        duration: 0.16,
        clearProps: "transform",
      },
      "-=0.1"
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
    duration: 0.2,
    ease: "power2.out",
  });
};

export const animateHoverButton = (el: HTMLElement | null, isEnter: boolean) => {
  if (!el) return;
  // Natural subtle brightness/border transition instead of cartoon scaling
  gsap.to(el, {
    y: isEnter ? -1 : 0,
    duration: 0.14,
    ease: "power2.out",
  });
};

export const animateHeaderEntrance = (
  headerEl: HTMLElement | null,
  navEl: HTMLElement | null,
  personaEl: HTMLElement | null
) => {
  const tl = gsap.timeline({ defaults: { ease: "power2.out" } });

  if (headerEl) {
    tl.fromTo(
      headerEl,
      { y: -8, opacity: 0 },
      { y: 0, opacity: 1, duration: 0.25 }
    );
  }

  if (personaEl) {
    tl.fromTo(
      personaEl,
      { opacity: 0 },
      { opacity: 1, duration: 0.2 },
      "-=0.1"
    );
  }

  if (navEl) {
    tl.fromTo(
      navEl.children,
      { opacity: 0 },
      { opacity: 1, stagger: 0.015, duration: 0.2 },
      "-=0.1"
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
  duration = 0.4
) => {
  if (!targetEl) return;
  const chars = "0123456789abcdefABCDEF";
  const length = finalText.length;
  let frame = 0;
  const totalFrames = Math.max(1, Math.floor(duration * 60));

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
  duration = 0.4,
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
 * Professional verification success flash (clean border highlight without neon blur)
 */
export const animateVerificationSuccess = (container: HTMLElement | null) => {
  if (!container) return;
  gsap.fromTo(
    container,
    { borderColor: "rgba(52, 211, 153, 0.9)" },
    { borderColor: "rgba(39, 39, 42, 0.8)", duration: 0.4, ease: "power2.out" }
  );
};

/**
 * High-precision subtle card hover interaction
 */
export const animateCardHover = (el: HTMLElement | null, isEnter: boolean) => {
  if (!el) return;
  gsap.to(el, {
    y: isEnter ? -1.5 : 0,
    duration: 0.16,
    ease: "power2.out",
  });
};

export interface StaggerOptions {
  yOffset?: number;
  staggerDelay?: number;
  duration?: number;
}

/**
 * Natural, fast entrance for cards - subtle 4px lift and crisp opacity without jarring scales
 */
export const animateCardsStagger = (
  target: HTMLElement | HTMLElement[] | NodeListOf<Element> | null,
  selectorOrOptions: string | number | StaggerOptions = ".aegis-card",
  options?: StaggerOptions
) => {
  if (!target) return;

  let elements: HTMLElement[] = [];
  let opts: StaggerOptions = {};

  if (typeof selectorOrOptions === "number") {
    opts.staggerDelay = selectorOrOptions;
    if (Array.isArray(target)) {
      elements = target;
    } else if (target instanceof HTMLElement && "querySelectorAll" in target) {
      elements = Array.from(target.querySelectorAll(".aegis-card")) as HTMLElement[];
    }
  } else if (typeof selectorOrOptions === "string") {
    if (target instanceof HTMLElement && "querySelectorAll" in target) {
      elements = Array.from(target.querySelectorAll(selectorOrOptions)) as HTMLElement[];
    } else if (Array.isArray(target)) {
      elements = target;
    }
    if (options) opts = options;
  } else if (typeof selectorOrOptions === "object") {
    opts = selectorOrOptions;
    if (Array.isArray(target)) {
      elements = target;
    } else if (target instanceof HTMLElement && "querySelectorAll" in target) {
      elements = Array.from(target.querySelectorAll(".aegis-card")) as HTMLElement[];
    }
  }

  if (Array.isArray(target) && elements.length === 0) {
    elements = target;
  }

  if (elements.length === 0) return;

  const yOffset = opts.yOffset ?? 4;
  const staggerDelay = opts.staggerDelay ?? 0.02;
  const duration = opts.duration ?? 0.18;

  gsap.fromTo(
    elements,
    { opacity: 0, y: yOffset },
    {
      opacity: 1,
      y: 0,
      stagger: staggerDelay,
      duration: duration,
      ease: "power2.out",
      clearProps: "transform",
    }
  );
};

/**
 * Clean hairline border highlight
 */
export const animateCircuitPulse = (el: HTMLElement | null) => {
  if (!el) return;
  gsap.fromTo(
    el,
    { borderColor: "rgba(52, 211, 153, 0.7)" },
    { borderColor: "rgba(39, 39, 42, 0.8)", duration: 0.5, ease: "power2.out" }
  );
};

