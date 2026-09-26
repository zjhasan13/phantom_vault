// Popup: credentials matching the active tab, 1-click Fill / Copy.
//
// Hang-proof: every bridge round-trip races a 10s timeout, so the popup can
// NEVER stick on "Loading…" — a dead bridge, a locked vault, or a sleeping
// service worker all land on one actionable message + a Retry button.
(async () => {
  const list = document.getElementById("list");
  const status = document.getElementById("status");
  const LOCKED_MSG = "🔒 Vault is locked. Please unlock PhantomVault desktop app.";
  const QUERY_TIMEOUT_MS = 10000;

  function showLocked(hint) {
    status.textContent = LOCKED_MSG + (hint ? " (" + hint + ")" : "");
    const retry = document.createElement("button");
    retry.textContent = "🔄 Retry";
    retry.addEventListener("click", () => window.location.reload());
    status.append(document.createElement("br"), retry);
  }

  function withTimeout(promise, ms, label) {
    let timer;
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(label + " timed out")), ms);
    });
    return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
  }

  let host = "";
  try {
    const [tab] = await withTimeout(
      chrome.tabs.query({ active: true, currentWindow: true }),
      QUERY_TIMEOUT_MS,
      "tab lookup"
    );
    host = tab && tab.url ? new URL(tab.url).host : "";
  } catch (_) {
    showLocked("no active tab");
    return;
  }

  let res;
  try {
    res = await withTimeout(
      chrome.runtime.sendMessage({ type: "PV_QUERY", app: host }),
      QUERY_TIMEOUT_MS,
      "vault bridge"
    );
  } catch (e) {
    // Bridge unreachable / host missing / worker asleep — one clean message.
    showLocked("bridge unreachable");
    return;
  }
  if (!res || !res.ok) {
    const err = (res && res.error) || "";
    if (/lock/i.test(err)) {
      showLocked();
    } else if (err) {
      status.textContent = "⚠️ " + err;
    } else {
      showLocked();
    }
    return;
  }
  const entries = res.entries || [];
  if (!entries.length) {
    status.textContent = `No credentials match “${host}”.`;
    return;
  }
  status.textContent = "";
  for (const e of entries.slice(0, 8)) {
    const row = document.createElement("div");
    row.className = "row";
    const t = document.createElement("div");
    t.className = "t";
    t.textContent = e.title || "(untitled)";
    const u = document.createElement("div");
    u.className = "u";
    u.textContent = e.username || "";
    const btns = document.createElement("div");
    btns.className = "btns";
    const fill = document.createElement("button");
    fill.className = "fill";
    fill.textContent = "⚡ Fill";
    fill.addEventListener("click", async () => {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab || tab.id == null) return;
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: (entry) => {
          const set = (el, v) => {
            if (!el) return;
            const proto = window.HTMLInputElement.prototype;
            Object.getOwnPropertyDescriptor(proto, "value").set.call(el, v);
            el.dispatchEvent(new Event("input", { bubbles: true }));
          };
          const pw = document.querySelector('input[type="password"]');
          const user = document.querySelector('input[type="text"], input[type="email"]');
          set(user, entry.username || "");
          set(pw, entry.password || "");
        },
        args: [{ username: e.username, password: e.password }],
      });
      window.close();
    });
    const copy = document.createElement("button");
    copy.textContent = "📋 Copy";
    copy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(e.password || "");
        copy.textContent = "✅ Copied";
      } catch (_) {
        copy.textContent = "⚠️ Blocked";
      }
    });
    btns.append(fill, copy);
    row.append(t, u, btns);
    list.append(row);
  }
})();
