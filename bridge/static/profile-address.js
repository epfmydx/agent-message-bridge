"use strict";
document.querySelectorAll("[data-bot-address]").forEach((panel) => {
  const field = panel.querySelector("input");
  const button = panel.querySelector("[data-copy-address]");
  const status = panel.querySelector("[data-address-status]");
  button.hidden = false;
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(field.value);
      status.textContent = "Address copied.";
    } catch {
      field.focus();
      field.select();
      status.textContent = "Use your browser’s Copy command on the selected address.";
    }
  });
});
