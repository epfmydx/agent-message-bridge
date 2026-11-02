"use strict";
// A new key exists only in this response; never persist it in browser storage.
document.querySelectorAll("[data-key-reveal]").forEach((panel) => {
  const field = panel.querySelector(".credential-secret");
  const toggle = panel.querySelector("[data-toggle-key]");
  const copy = panel.querySelector("[data-copy-key]");
  const status = panel.querySelector("[data-copy-status]");
  toggle.hidden = false;
  copy.hidden = false;
  toggle.addEventListener("click", () => {
    const reveal = field.type === "password";
    field.type = reveal ? "text" : "password";
    toggle.textContent = reveal ? "Hide key" : "Show key";
    toggle.setAttribute("aria-pressed", String(reveal));
  });
  copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(field.value);
      status.textContent = "Key copied.";
    } catch {
      field.focus();
      field.select();
      status.textContent = field.type === "password"
        ? "Copy is unavailable. Show the key, select it and use your browser’s Copy command."
        : "Copy is unavailable. Use your browser’s Copy command on the selected key.";
    }
  });
  window.addEventListener("pagehide", () => {
    // A browser back/forward cache must not restore the one-time secret.
    field.value = "";
    field.removeAttribute("value");
    field.type = "password";
    toggle.hidden = true;
    copy.hidden = true;
    status.textContent = "This key is no longer available here. Return to Credentials to manage its key ID.";
  });
});
