// Popup: credentials matching the active tab, 1-click Fill / Copy.
(async () => {
  const list = document.getElementById("list");
  const status = document.getElementById("status");
  let host = "";
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    host = tab && tab.url ? new URL(tab.url).host : "";
  } catch (_) { /* no tab access */ }

  let res;
  try {
    res = await chrome.runtime.sendMessage({ type: "PV_QUERY", app: host });
  } catch (e) {
    status.textContent = "Bridge unreachable — install the native host first.";
    return;
  }
  if (!res || !res.ok) {
    status.textContent = (res && res.error) || "Vault locked — unlock PhantomVault first.";
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
