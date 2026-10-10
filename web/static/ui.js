/* Shared navigation, motion and accessible dialogs. App data stays in app.js. */
(() => {
  "use strict";
  const motion = window.matchMedia("(prefers-reduced-motion: reduce)");
  let lenis = null;
  const animations = new Set();
  function animate(target, options) {
    if (motion.matches || !window.anime) return;
    const animation = window.anime.animate(target, {
      duration: 560,
      ease: "out(3)",
      ...options,
      onComplete: (self) => animations.delete(self),
    });
    animations.add(animation);
    return animation;
  }
  function toast(message, type = "info") {
    const region = document.getElementById("toast-region");
    if (!region) return;
    const item = document.createElement("div");
    item.className = `toast ${["error", "success", "warning"].includes(type) ? type : "info"}`;
    const text = document.createElement("span");
    text.textContent = message;
    const close = document.createElement("button");
    close.type = "button";
    close.textContent = "×";
    close.setAttribute("aria-label", "Bildirimi kapat");
    close.addEventListener("click", () => item.remove());
    item.append(text, close);
    while (region.children.length >= 4) region.firstElementChild.remove();
    region.append(item);
    animate(item, { opacity: [0, 1], y: [12, 0], duration: 260 });
    setTimeout(() => item.remove(), 6000);
  }
  window.DSUI = {
    toast,
    animate,
    get reducedMotion() {
      return motion.matches;
    },
  };

  document.addEventListener("DOMContentLoaded", () => {
    const date = document.getElementById("current-date");
    if (date)
      date.textContent = new Intl.DateTimeFormat("tr-TR", {
        day: "numeric",
        month: "long",
        year: "numeric",
      }).format(new Date());
    function configureMotion() {
      animations.forEach((animation) => animation.complete());
      animations.clear();
      if (lenis) {
        lenis.destroy();
        lenis = null;
      }
      if (!motion.matches && window.Lenis) {
        lenis = new window.Lenis({
          autoRaf: true,
          duration: 0.85,
          anchors: { offset: -85 },
          prevent: (node) => node.hasAttribute("data-lenis-prevent"),
        });
        if (document.body.matches(".modal-open, .nav-open")) lenis.stop();
      }
    }
    configureMotion();
    motion.addEventListener("change", configureMotion);
    const reveal = new IntersectionObserver(
      (entries) => {
        const entering = entries.filter((entry) => entry.isIntersecting);
        entering.forEach((entry) => reveal.unobserve(entry.target));
        if (entering.length)
          animate(
            entering.map((entry) => entry.target),
            {
              opacity: [0.45, 1],
              y: [16, 0],
              delay: window.anime ? window.anime.stagger(55) : 0,
            },
          );
      },
      { threshold: 0.08 },
    );
    document
      .querySelectorAll("[data-reveal]")
      .forEach((element) => reveal.observe(element));

    const nav = document.getElementById("app-nav");
    const workspace = document.querySelector(".app-workspace");
    const toggle = document.querySelector("[data-toggle-nav]");
    const mobile = matchMedia("(max-width: 960px)");
    let returnFocus = null;
    function closeNav() {
      document.body.classList.remove("nav-open");
      if (toggle) toggle.setAttribute("aria-expanded", "false");
      if (workspace) workspace.inert = false;
      if (nav) nav.inert = mobile.matches;
      lenis?.start();
    }
    closeNav();
    mobile.addEventListener("change", closeNav);
    toggle?.addEventListener("click", () => {
      if (!mobile.matches) return;
      returnFocus = document.activeElement;
      document.body.classList.add("nav-open");
      toggle.setAttribute("aria-expanded", "true");
      nav.inert = false;
      nav.querySelector("a").focus();
      workspace.inert = true;
      lenis?.stop();
    });
    document
      .querySelector("[data-close-nav]")
      ?.addEventListener("click", () => {
        closeNav();
        returnFocus?.focus();
      });
    document.querySelectorAll(".nav-link[href]").forEach((link) =>
      link.addEventListener("click", () => {
        closeNav();
        const url = new URL(link.href);
        if (url.pathname === location.pathname && url.hash) {
          const target = document.getElementById(url.hash.slice(1));
          target?.setAttribute("tabindex", "-1");
          target?.focus({ preventScroll: true });
        }
      }),
    );
    const sections = [...document.querySelectorAll(".page-section[id]")];
    const highlightNav = () => {
      let current = sections[0]?.id;
      for (const section of sections)
        if (section.getBoundingClientRect().top <= 160) current = section.id;
      document.querySelectorAll(".nav-link[data-section]").forEach((link) => {
        const active = link.dataset.section === current;
        link.classList.toggle("active", active);
        if (active) link.setAttribute("aria-current", "location");
        else link.removeAttribute("aria-current");
      });
    };
    if (sections.length) {
      let ticking = false;
      window.addEventListener(
        "scroll",
        () => {
          if (!ticking) {
            ticking = true;
            requestAnimationFrame(() => {
              highlightNav();
              ticking = false;
            });
          }
        },
        { passive: true },
      );
      highlightNav();
    }

    // Observe legacy modal open/close calls, preserving their API and focus behavior.
    const dialogs = [...document.querySelectorAll('[role="dialog"]')];
    let activeDialog = null;
    let dialogTrigger = null;
    const focusable = (container) =>
      [
        ...container.querySelectorAll(
          'a[href],button,input,textarea,select,[tabindex="0"]',
        ),
      ].filter(
        (element) =>
          !element.disabled &&
          !element.closest("[inert]") &&
          element.getClientRects().length,
      );
    function syncDialogs() {
      const next =
        dialogs.find((dialog) => getComputedStyle(dialog).display !== "none") ||
        null;
      if (next === activeDialog) return;
      if (next) {
        if (!activeDialog) dialogTrigger = document.activeElement;
        closeNav();
        activeDialog = next;
        document.body.classList.add("modal-open");
        if (workspace) workspace.inert = true;
        if (nav) nav.inert = true;
        lenis?.stop();
        next.setAttribute("tabindex", "-1");
        (focusable(next)[0] || next).focus({ preventScroll: true });
        animate(next.querySelector(".modal-content, .port-modal"), {
          opacity: [0.5, 1],
          y: [10, 0],
          duration: 220,
        });
      } else {
        activeDialog = null;
        document.body.classList.remove("modal-open");
        if (workspace) workspace.inert = false;
        if (nav) nav.inert = mobile.matches;
        lenis?.start();
        if (dialogTrigger?.isConnected && !dialogTrigger.closest("[inert]"))
          dialogTrigger.focus({ preventScroll: true });
        else toggle?.focus({ preventScroll: true });
      }
    }
    function closeDialog(dialog) {
      if (!dialog) return;
      if (dialog.id === "traffic-modal" && window.closeTrafficModal)
        window.closeTrafficModal();
      else if (dialog.id === "port-modal") dialog.classList.remove("active");
      else dialog.style.display = "none";
    }
    const dialogObserver = new MutationObserver(syncDialogs);
    dialogs.forEach((dialog) => {
      dialogObserver.observe(dialog, {
        attributes: true,
        attributeFilter: ["style", "class"],
      });
      dialog.addEventListener("click", (event) => {
        if (
          event.target === dialog ||
          event.target.closest("[data-close-modal]")
        )
          closeDialog(dialog);
      });
    });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        if (activeDialog) closeDialog(activeDialog);
        else if (document.body.classList.contains("nav-open")) {
          closeNav();
          returnFocus?.focus();
        }
      }
      const trap =
        activeDialog ||
        (document.body.classList.contains("nav-open") ? nav : null);
      if (event.key !== "Tab" || !trap) return;
      const items = focusable(trap);
      if (!items.length) {
        event.preventDefault();
        trap.focus();
        return;
      }
      if (
        event.shiftKey &&
        (document.activeElement === items[0] || document.activeElement === trap)
      ) {
        event.preventDefault();
        items.at(-1).focus();
      } else if (!event.shiftKey && document.activeElement === items.at(-1)) {
        event.preventDefault();
        items[0].focus();
      }
    });
    document
      .querySelector(".password-toggle")
      ?.addEventListener("click", (event) => {
        const field = document.getElementById("password");
        const visible = field.type === "password";
        field.type = visible ? "text" : "password";
        event.currentTarget.textContent = visible ? "Gizle" : "Göster";
        event.currentTarget.setAttribute(
          "aria-label",
          visible ? "Parolayı gizle" : "Parolayı göster",
        );
        event.currentTarget.setAttribute("aria-pressed", String(visible));
      });
    document.querySelectorAll(".segmented").forEach((group) =>
      group.addEventListener("click", (event) => {
        const button = event.target.closest("button");
        if (!button) return;
        group
          .querySelectorAll("button")
          .forEach((item) =>
            item.setAttribute("aria-pressed", String(item === button)),
          );
      }),
    );
    window.addEventListener("pagehide", (event) => {
      if (!event.persisted) {
        lenis?.destroy();
        reveal.disconnect();
        dialogObserver.disconnect();
      }
    });
  });
})();
