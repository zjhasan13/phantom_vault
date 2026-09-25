// PhantomVault content script: badge password fields, fill on demand.
(() => {
  const BADGE_CLASS = "pv-shield-badge";

  function isVisible(el) {
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== "hidden";
  }

  function findFields() {
    const pass = [...document.querySelectorAll('input[type="password"]')].filter(isVisible);
    const users = [...document.querySelectorAll(
      'input[type="text"][name*="user" i], input[type="text"][name*="login" i], ' +
      'input[type="email"], input[type="text"][autocomplete*="username" i]'
    )].filter(isVisible);
    const otp = [...document.querySelectorAll(
      'input[inputmode="numeric"], input[name*="otp" i], input[name*="code" i][maxlength]'
    )].filter((el) => isVisible(el) && (el.maxLength <= 0 || el.maxLength <= 10));
    return { pass, users, otp };
  }

  function placeBadge(field) {
    if (field.dataset.pvBadged) return;
    field.dataset.pvBadged = "1";
    const b = document.createElement("button");
    b.type = "button";
    b.className = BADGE_CLASS;
    b.title = "Fill with PhantomVault";
    b.textContent = "🛡️";
    b.style.cssText =
      "position:absolute;z-index:2147483647;width:26px;height:26px;margin-left:-30px;" +
      "border:1px solid #8b7cf6;border-radius:8px;background:#0d1430;cursor:pointer;font-size:14px;";
    b.addEventListener("click", async (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      await fillFromVault();
    });
    field.insertAdjacentElement("afterend", b);
  }

  function setNativeValue(el, value) {
    const proto = el.tagName === "TEXTAREA"
      ? window.HTMLTextAreaElement.prototype
      : window.HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, "value").set;
    setter.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  async function fillFromVault() {
    const { pass, users } = findFields();
    if (!pass.length) return;
    let res;
    try {
      res = await chrome.runtime.sendMessage({ type: "PV_QUERY", app: location.host });
    } catch (_) {
      return;
    }
    if (!res || !res.ok || !res.entries || !res.entries.length) return;
    const e = res.entries[0];
    const userField = users[0] || null;
    if (userField && e.username) setNativeValue(userField, e.username);
    if (e.password) setNativeValue(pass[0], e.password);
  }

  function scan() {
    const { pass } = findFields();
    pass.forEach(placeBadge);
  }

  scan();
  new MutationObserver(scan).observe(document.documentElement, {
    childList: true,
    subtree: true,
  });
})();
