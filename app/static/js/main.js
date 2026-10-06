/* =============================================================
   PhishGuard — main.js
   Covers: Alert auto-dismiss, show/hide password, form
   loading states, mobile nav, URL input clear, accessibility.
   ============================================================= */

(function () {
  "use strict";

  /* ── Helpers ───────────────────────────────────────────── */
  function qs(sel, ctx) { return (ctx || document).querySelector(sel); }
  function qsa(sel, ctx) { return Array.from((ctx || document).querySelectorAll(sel)); }

  /* ── Alert auto-dismiss ────────────────────────────────── */
  /**
   * Flash alerts dismiss after 5 s with a fade-out.
   * Skips danger/error alerts so users must dismiss them manually.
   */
  function initAlerts() {
    qsa(".alert").forEach(function (el) {
      if (el.classList.contains("alert-danger")) return; // keep errors visible
      var delay = 5000;
      var timer = setTimeout(function () { dismissAlert(el); }, delay);

      // Pause on hover
      el.addEventListener("mouseenter", function () { clearTimeout(timer); });
      el.addEventListener("mouseleave", function () {
        timer = setTimeout(function () { dismissAlert(el); }, 2000);
      });
    });
  }

  function dismissAlert(el) {
    el.style.transition = "opacity 0.4s ease, max-height 0.4s ease, margin 0.4s ease";
    el.style.opacity = "0";
    el.style.maxHeight = el.offsetHeight + "px";
    requestAnimationFrame(function () {
      el.style.maxHeight = "0";
      el.style.marginBottom = "0";
    });
    setTimeout(function () { el.remove(); }, 450);
  }

  /* ── Show / hide password ──────────────────────────────── */
  /**
   * Called from onclick in templates: togglePassword(inputId, btn)
   * Exported to window so inline handlers can reach it.
   */
  window.togglePassword = function (inputId, btn) {
    var input = document.getElementById(inputId);
    if (!input) return;
    var isText = input.type === "text";
    input.type = isText ? "password" : "text";
    var icon = btn.querySelector("span");
    if (icon) icon.textContent = isText ? "👁" : "🙈";
    btn.setAttribute("aria-label", isText ? "Show password" : "Hide password");
  };

  /* ── Mobile nav toggle ─────────────────────────────────── */
  function initMobileNav() {
    var toggle = qs(".nav-toggle");
    var links  = qs(".nav-links");
    var user   = qs(".nav-user");
    if (!toggle) return;

    toggle.addEventListener("click", function () {
      var expanded = toggle.getAttribute("aria-expanded") === "true";
      toggle.setAttribute("aria-expanded", String(!expanded));
      if (links) links.classList.toggle("open");
      if (user)  user.classList.toggle("open");
    });

    // Close on outside click
    document.addEventListener("click", function (e) {
      if (!toggle.contains(e.target) &&
          !(links && links.contains(e.target)) &&
          !(user  && user.contains(e.target))) {
        toggle.setAttribute("aria-expanded", "false");
        if (links) links.classList.remove("open");
        if (user)  user.classList.remove("open");
      }
    });
  }

  /* ── Form loading state ────────────────────────────────── */
  /**
   * Attaches a loading state to any form with data-loading="true".
   * The submit button should contain .btn-text and .btn-loader children.
   */
  function initFormLoading() {
    qsa("form[data-loading]").forEach(function (form) {
      form.addEventListener("submit", function () {
        var btn    = form.querySelector("[type=submit]");
        var text   = btn && btn.querySelector(".btn-text");
        var loader = btn && btn.querySelector(".btn-loader");
        if (!btn) return;
        btn.disabled = true;
        if (text)   text.textContent = btn.dataset.loadingText || "Loading…";
        if (loader) loader.classList.remove("hidden");
      });
    });
  }

  /* ── Animate risk bar on result page ───────────────────── */
  function initRiskBar() {
    qsa(".risk-bar__fill").forEach(function (bar) {
      var target = bar.style.width;
      bar.style.width = "0%";
      setTimeout(function () { bar.style.width = target; }, 120);
    });
  }

  /* ── Animate summary card numbers (count-up) ───────────── */
  function initCountUp() {
    qsa(".summary-card__value").forEach(function (el) {
      var target = parseInt(el.textContent, 10);
      if (isNaN(target) || target === 0) return;
      var duration = 600;
      var start    = performance.now();
      function step(now) {
        var elapsed  = now - start;
        var progress = Math.min(elapsed / duration, 1);
        var eased    = 1 - Math.pow(1 - progress, 3); // ease-out cubic
        el.textContent = Math.round(eased * target);
        if (progress < 1) requestAnimationFrame(step);
      }
      requestAnimationFrame(step);
    });
  }

  /* ── Accessible active nav link ────────────────────────── */
  function initActiveNav() {
    qsa(".nav-links a.active").forEach(function (a) {
      a.setAttribute("aria-current", "page");
    });
  }

  /* ── Bootstrap ─────────────────────────────────────────── */
  document.addEventListener("DOMContentLoaded", function () {
    initAlerts();
    initMobileNav();
    initFormLoading();
    initRiskBar();
    initCountUp();
    initActiveNav();
  });

})();
