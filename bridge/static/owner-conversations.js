/* Owner-only read views. No read receipts, claims or message mutations. */
(() => {
  "use strict";
  const list = document.querySelector("[data-owner-list]");
  const listURLKey = "agent-message-bridge-owner-list-url";
  const stateKey = `agent-message-bridge-owner-list:${location.pathname}${location.search}`;
  const readState = key => { try { return JSON.parse(sessionStorage.getItem(key)); } catch { return null; } };
  const saveState = (key, value) => { try { sessionStorage.setItem(key, JSON.stringify(value)); } catch { /* Browser storage can be disabled. */ } };
  if (list) {
    let refreshing = false;
    const pairForm = list.querySelector(".pair-filter");
    if (pairForm) {
      const first = pairForm.elements.namedItem("participant_a");
      const second = pairForm.elements.namedItem("participant_b");
      const validatePair = () => second.setCustomValidity(first.value && first.value === second.value ? "Choose two different profiles." : "");
      first.addEventListener("change", validatePair);
      second.addEventListener("change", validatePair);
      validatePair();
    }
    const save = () => {
      if (refreshing) return;
      const row = [...list.querySelectorAll("[data-thread-id]")].find(item => item.getBoundingClientRect().bottom > 0);
      saveState(stateKey, { y: window.scrollY, anchor: row?.dataset.threadId, offset: row?.getBoundingClientRect().top });
      saveState(listURLKey, `${location.pathname}${location.search}`);
    };
    const state = readState(stateKey);
    if (state && Number.isFinite(state.y)) requestAnimationFrame(() => {
      const row = [...list.querySelectorAll("[data-thread-id]")].find(item => item.dataset.threadId === state.anchor);
      window.scrollTo(0, row && Number.isFinite(state.offset) ? window.scrollY + row.getBoundingClientRect().top - state.offset : state.y);
    });
    list.addEventListener("click", event => {
      const refresh = event.target.closest("[data-refresh-conversations]");
      if (refresh) {
        refreshing = true;
        const target = new URL(refresh.href, location.href);
        try { sessionStorage.removeItem(`agent-message-bridge-owner-list:${target.pathname}${target.search}`); } catch { /* Native navigation still works. */ }
      } else save();
    });
    window.addEventListener("pagehide", save);
    return;
  }

  const page = document.querySelector("[data-owner-conversation]");
  if (!page) return;
  const scroll = page.querySelector("[data-message-scroll]");
  const messages = page.querySelector("[data-messages]");
  const olderControl = page.querySelector("[data-load-older]");
  const historyStatus = page.querySelector("[data-history-status]");
  const signIn = page.querySelector("[data-sign-in]");
  const status = page.querySelector("[data-conversation-status]");
  const jump = page.querySelector("[data-jump-latest]");
  const check = page.querySelector("[data-check-new]");
  const back = page.querySelector("[data-back-list]");
  let olderURL = page.dataset.olderUrl || null;
  let newerURL = page.dataset.newerUrl;
  let epoch = 0;
  let departing = false;
  let signedOut = false;
  let newMessages = false;
  let connectionFailed = false;
  let olderError = "";
  let announcement = 0;
  let lastTop = 0;
  const historyPage = new URL(location.href).searchParams.has("cursor");
  const active = new Map();
  const feedPath = new URL(newerURL, location.href).pathname;
  const nearBottom = () => scroll.scrollHeight - scroll.clientHeight - scroll.scrollTop <= 24;
  const say = text => {
    const ownAnnouncement = ++announcement;
    // A separate update lets polite live regions announce identical outcomes.
    // Cancel an older queued announcement when a newer state supersedes it.
    status.textContent = "";
    requestAnimationFrame(() => requestAnimationFrame(() => {
      if (ownAnnouncement === announcement && !departing) status.textContent = text;
    }));
  };
  const feedURL = value => {
    if (!value) return null;
    const url = new URL(value, location.href);
    if (url.origin !== location.origin || url.pathname !== feedPath || url.searchParams.get("thread_id") !== page.dataset.threadId) throw new Error("Invalid history link");
    return url.href;
  };
  const htmlPageURL = value => {
    const url = new URL(value, location.href);
    url.pathname = location.pathname;
    return `${url.pathname}${url.search}`;
  };
  const latestURL = () => {
    const url = new URL(location.href);
    url.searchParams.delete("cursor");
    return url.href;
  };
  const focus = node => node.focus({ preventScroll: true });
  const updateJump = () => {
    const hide = !newMessages && nearBottom() && !historyPage;
    if (hide && document.activeElement === jump) focus(scroll);
    jump.hidden = hide;
  };
  const anchor = () => {
    const top = scroll.getBoundingClientRect().top + 1;
    const node = [...messages.children].find(item => item.getBoundingClientRect().bottom > top);
    return node ? { node, top: node.getBoundingClientRect().top } : null;
  };
  const resize = () => {
    const follow = nearBottom() && !historyPage;
    const held = anchor();
    const height = Math.max(240, window.innerHeight - scroll.getBoundingClientRect().top - 88);
    scroll.style.height = `${height}px`;
    if (follow) scroll.scrollTop = scroll.scrollHeight;
    else if (held) scroll.scrollTop += held.node.getBoundingClientRect().top - held.top;
    lastTop = scroll.scrollTop;
    updateJump();
  };
  const setOlderState = () => {
    const busy = active.has("older");
    olderControl.hidden = !olderURL || signedOut;
    olderControl.setAttribute("aria-disabled", String(busy));
    olderControl.setAttribute("aria-busy", String(busy));
    olderControl.textContent = busy ? "Loading older messages…" : "Load older messages";
    if (olderURL) olderControl.href = htmlPageURL(olderURL);
    historyStatus.hidden = signedOut || (Boolean(olderURL) && !olderError);
    historyStatus.textContent = olderError || "Beginning of conversation";
  };
  const expired = () => {
    const transferFocus = document.activeElement === check || document.activeElement === olderControl;
    signedOut = true;
    signIn.hidden = false;
    if (transferFocus) focus(signIn);
    check.hidden = true;
    olderControl.hidden = true;
    historyStatus.hidden = true;
    if (transferFocus) signIn.scrollIntoView({ block: "nearest" });
    say("Your session ended. Sign in to continue.");
  };
  const fragment = html => {
    if (typeof html !== "string") throw new Error("Invalid history response");
    const template = document.createElement("template");
    template.innerHTML = html;
    const existing = new Set([...messages.children].map(node => node.dataset.messageId));
    const output = document.createDocumentFragment();
    for (const node of [...template.content.children]) {
      if (!node.matches("article[data-message-id][data-sequence][data-thread-id]") || node.dataset.threadId !== page.dataset.threadId || !/^\d+$/.test(node.dataset.sequence)) throw new Error("Invalid history item");
      if (!existing.has(node.dataset.messageId)) {
        existing.add(node.dataset.messageId);
        output.append(node);
      }
    }
    return output;
  };

  async function load(kind, manual = false, keyboard = false) {
    const target = kind === "older" ? olderURL : newerURL;
    if (!target || active.has(kind) || departing || signedOut || (kind === "newer" && document.hidden && !manual)) return;
    const controller = new AbortController();
    const ownEpoch = epoch;
    active.set(kind, controller);
    const startingAnchor = anchor();
    if (kind === "older") olderError = "";
    setOlderState();
    if (startingAnchor) scroll.scrollTop += startingAnchor.node.getBoundingClientRect().top - startingAnchor.top;
    lastTop = scroll.scrollTop;
    if (manual && kind === "newer") say("Checking for new messages…");
    const timeout = setTimeout(() => controller.abort(), 20000);
    let more = false;
    try {
      const response = await fetch(feedURL(target), { credentials: "same-origin", cache: "no-store", redirect: "error", headers: { Accept: "application/json" }, signal: controller.signal });
      if (ownEpoch !== epoch || departing || signedOut) return;
      if (response.status === 401) { expired(); return; }
      if (!response.ok || !(response.headers.get("Content-Type") || "").includes("application/json")) throw new Error("History unavailable");
      const data = await response.json();
      if (ownEpoch !== epoch || departing || signedOut) return;
      const nextOlder = feedURL(data.older_url);
      const nextNewer = feedURL(data.newer_url);
      if (!nextNewer || typeof data.has_more !== "boolean") throw new Error("Invalid history boundary");
      const nodes = fragment(data.html);
      const wasDisconnected = connectionFailed;
      connectionFailed = false;
      const count = nodes.childElementCount;
      const firstNew = nodes.firstElementChild;
      const follow = kind === "newer" && nearBottom() && !historyPage;
      const focusedOlder = document.activeElement === olderControl;
      const held = kind === "older" ? (!manual && focusedOlder && nextOlder
        ? { node: olderControl, top: olderControl.getBoundingClientRect().top }
        : anchor()) : null;
      if (kind === "older") messages.prepend(nodes); else messages.append(nodes);
      if (count) page.querySelector("[data-conversation-empty]")?.remove();
      if (kind === "older") olderURL = nextOlder;
      else { newerURL = nextNewer; more = data.has_more; }
      if (kind === "older" && focusedOlder && (manual || !olderURL)) {
        if (keyboard && firstNew) {
          firstNew.setAttribute("tabindex", "-1");
          focus(firstNew);
        } else focus(scroll);
      }
      // Render the final control height before restoring the message anchor.
      active.delete(kind);
      setOlderState();
      // Disable native scroll anchoring and compensate by the same visible
      // message, measured when the response lands, not when it was requested.
      if (held) scroll.scrollTop += held.node.getBoundingClientRect().top - held.top;
      else if (follow) scroll.scrollTop = scroll.scrollHeight;
      if (kind === "older" && focusedOlder && keyboard && firstNew) {
        scroll.scrollTop += firstNew.getBoundingClientRect().top - scroll.getBoundingClientRect().top - 12;
      }
      lastTop = scroll.scrollTop;
      if (kind === "older") say(count ? "Older messages loaded." : "Beginning of conversation.");
      else if (count && !follow) { newMessages = true; say("New messages available."); }
      else if (count) say(`${count} new ${count === 1 ? "message" : "messages"} received.`);
      else if (manual) say(newMessages ? "New messages available." : "No new messages.");
      else if (wasDisconnected) say(nearBottom() ? "Latest messages" : "Conversation history");
      updateJump();
    } catch (error) {
      if (!departing && ownEpoch === epoch && !signedOut) {
        if (kind === "older") {
          olderError = "Couldn’t load older messages. Try again.";
          say("Older messages couldn’t be loaded. Try again.");
        } else { connectionFailed = true; say("Connection interrupted. Showing loaded messages."); }
      }
    } finally {
      clearTimeout(timeout);
      if (active.get(kind) === controller) {
        const held = anchor();
        active.delete(kind);
        setOlderState();
        if (held) scroll.scrollTop += held.node.getBoundingClientRect().top - held.top;
        lastTop = scroll.scrollTop;
      }
      if (more && !departing && ownEpoch === epoch) setTimeout(() => load("newer"), 0);
    }
  }

  const previous = readState(listURLKey);
  if (typeof previous === "string") {
    try {
      const url = new URL(previous, location.href);
      const allowed = ["cursor", "page_size", "participant_a", "participant_b"];
      const selected = new URL(back.href, location.href);
      const pair = value => [value.searchParams.get("participant_a"), value.searchParams.get("participant_b")].sort();
      if (url.origin === location.origin && url.pathname === "/" &&
          [...url.searchParams.keys()].every(key => allowed.includes(key) && url.searchParams.getAll(key).length === 1) &&
          JSON.stringify(pair(url)) === JSON.stringify(pair(selected))) back.href = `${url.pathname}${url.search}`;
    } catch { /* Keep the ordinary server-rendered link. */ }
  }
  olderControl.addEventListener("click", event => { event.preventDefault(); load("older", true, event.detail === 0); });
  check.addEventListener("click", () => { if (historyPage) location.assign(latestURL()); else load("newer", true); });
  jump.addEventListener("click", () => {
    if (historyPage) { location.assign(latestURL()); return; }
    newMessages = false;
    const latest = messages.lastElementChild;
    if (latest) { latest.setAttribute("tabindex", "-1"); focus(latest); }
    else focus(scroll);
    scroll.scrollTop = scroll.scrollHeight;
    lastTop = scroll.scrollTop;
    say("Latest messages");
    updateJump();
  });
  scroll.addEventListener("scroll", () => {
    const movingUp = scroll.scrollTop < lastTop;
    lastTop = scroll.scrollTop;
    if (nearBottom() && newMessages) {
      newMessages = false;
      if (!connectionFailed && !signedOut) say("Latest messages");
    }
    updateJump();
    // Native focus scrolling to this link must not activate it implicitly.
    if (movingUp && scroll.scrollTop <= 64 && document.activeElement !== olderControl) load("older");
  }, { passive: true });
  window.addEventListener("resize", resize);
  window.addEventListener("pagehide", () => {
    departing = true;
    epoch += 1;
    for (const controller of active.values()) controller.abort();
  });
  window.addEventListener("pageshow", event => {
    if (event.persisted) { departing = false; resize(); }
  });
  document.addEventListener("visibilitychange", () => { if (!document.hidden && !historyPage) load("newer"); });
  setOlderState();
  requestAnimationFrame(() => {
    resize();
    scroll.scrollTop = scroll.scrollHeight;
    lastTop = scroll.scrollTop;
    if (historyPage) { say("Earlier messages"); check.textContent = "Latest messages"; }
    updateJump();
  });
  setInterval(() => { if (!historyPage) load("newer"); }, 15000);
})();
