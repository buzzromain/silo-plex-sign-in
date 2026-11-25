(function () {
  "use strict";

  document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  });

  document.querySelectorAll("[data-copy]").forEach((button) => {
    button.hidden = false;
    button.addEventListener("click", async () => {
      const status = button.parentElement.querySelector("[data-copy-status]") || button.nextElementSibling;
      try {
        if (navigator.clipboard && window.isSecureContext) {
          try {
            await navigator.clipboard.writeText(button.dataset.copy);
          } catch (_) {
            if (!copyWithSelection(button.dataset.copy)) throw new Error("Clipboard blocked");
          }
        } else if (!copyWithSelection(button.dataset.copy)) {
          throw new Error("Clipboard unavailable");
        }
        status.classList.remove("is-error");
        status.textContent = button.dataset.copied;
        button.classList.add("is-copied");
      } catch (_) {
        button.classList.remove("is-copied");
        status.classList.add("is-error");
        status.textContent = button.dataset.copyError;
      }
      clearTimeout(button.copyTimer);
      button.copyTimer = setTimeout(() => {
        button.classList.remove("is-copied");
        status.textContent = "";
      }, 2500);
    });
  });

  function copyWithSelection(value) {
    const field = document.createElement("textarea");
    field.value = value;
    field.setAttribute("readonly", "");
    field.style.position = "fixed";
    field.style.opacity = "0";
    document.body.appendChild(field);
    field.select();
    let copied = false;
    try { copied = document.execCommand("copy"); } catch (_) { /* Browser blocked the fallback. */ }
    field.remove();
    return copied;
  }

  const filter = document.getElementById("people-filter");
  if (filter) {
    filter.parentElement.hidden = false;
    filter.addEventListener("input", () => {
      const query = filter.value.trim().toLocaleLowerCase();
      document.querySelectorAll("[data-person]").forEach((row) => {
        row.hidden = !row.querySelector(".person").textContent.toLocaleLowerCase().includes(query);
      });
    });
  }
  document.querySelectorAll(".avatar img").forEach((image) => {
    image.addEventListener("error", () => { image.hidden = true; });
    if (image.complete && !image.naturalWidth) image.hidden = true;
  });

  document.querySelectorAll("[data-local-date]").forEach((node) => {
    const date = new Date(node.dataset.localDate);
    if (Number.isNaN(date.getTime())) return;
    node.textContent = new Intl.DateTimeFormat(document.documentElement.lang || undefined, {
      day: "numeric", month: "short", hour: "2-digit", minute: "2-digit",
    }).format(date);
  });

  const match = document.getElementById("ref-match");
  if (match) match.scrollIntoView({block: "center"});

  const finder = document.getElementById("finder");
  if (!finder) return;
  const resume = new URL(finder.dataset.resume, window.location.href);
  const link = document.getElementById("plex-connect");
  if (link) link.href += "&forwardUrl=" + encodeURIComponent(resume.href);
  const headers = {"Content-Type": "application/x-www-form-urlencoded"};
  function post(url, values) {
    return fetch(url, {method: "POST", headers, body: new URLSearchParams(values), credentials: "same-origin", cache: "no-store"});
  }
  const start = document.getElementById("finder-start");
  if (start) {
    start.addEventListener("submit", async (event) => {
      event.preventDefault();
      try {
        const response = await post(start.action, {token: finder.dataset.token});
        if (response.redirected) {
          window.location.assign(response.url);
          return;
        }
        const location = response.headers.get("Location");
        if (location) {
          window.location.assign(new URL(location, window.location.href));
          return;
        }
        window.location.reload();
      } catch (_) {
        window.location.reload();
      }
    });
  }
  if (!finder.dataset.status || !finder.dataset.flow) return;
  async function poll() {
    try {
      const response = await post(finder.dataset.status, {token: finder.dataset.pollToken, flow: finder.dataset.flow});
      const result = await response.json();
      if (result.status !== "waiting") { window.location.replace(resume); return; }
    } catch (_) { /* Keep the manual reload link usable. */ }
    window.setTimeout(poll, 2000);
  }
  window.setTimeout(poll, 2000);
})();
