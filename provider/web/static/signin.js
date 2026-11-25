// Plex Sign-In: polls the status API and switches between the screens the
// server rendered. Text comes from the server; this script only shows,
// hides and fills in values with textContent.
(function () {
  "use strict";

  var root = document.getElementById("signin");
  if (!root) {
    return;
  }
  var strings = {};
  try {
    strings = JSON.parse(document.getElementById("i18n").textContent) || {};
  } catch (e) {
    strings = {};
  }

  var statusURL = root.dataset.statusUrl;
  var statusToken = root.dataset.statusToken;
  var flowID = root.dataset.flow;
  var returnURL = root.dataset.returnUrl;
  var expiresAt = Date.parse(root.dataset.expiresAt || "");
  var finished = root.dataset.screen === "error";
  var failures = 0;
  var announced = false;
  var timer = null;
  var redirectTimer = null;

  // Keep the browser's claim in the address bar so a reload, or Plex sending
  // the browser back, reopens this same sign-in.
  var safeReturnURL = returnURL ? new URL(returnURL, window.location.href) : null;
  var sameOriginReturn = safeReturnURL && safeReturnURL.origin === window.location.origin;
  if (sameOriginReturn && window.history && history.replaceState) {
    try {
      history.replaceState(null, "", safeReturnURL);
    } catch (e) {
      // Ignore: the page still works without it.
    }
  }

  function show(id) {
    root.querySelectorAll(":scope > section").forEach(function (section) {
      section.hidden = section.id !== id;
    });
    root.dataset.screen = id;
  }

  function fillIdentity(account) {
    root.querySelectorAll("[data-identity]").forEach(function (chip) {
      if (!account) {
        return;
      }
      var name = account.title || account.username || "";
      chip.querySelector("[data-title]").textContent = name;
      chip.querySelector("[data-username]").textContent = account.title ? account.username || "" : "";
      chip.querySelector("[data-initials]").textContent = initials(name);
      var img = chip.querySelector("[data-thumb]");
      if (account.thumb) {
        img.addEventListener("error", function () { img.hidden = true; }, { once: true });
        img.src = account.thumb;
        img.hidden = false;
      }
      chip.hidden = false;
    });
  }

  function initials(name) {
    var parts = String(name).replace(/^@/, "").trim().split(/\s+/);
    if (!parts[0]) {
      return "?";
    }
    return (parts[0][0] + (parts[1] ? parts[1][0] : "")).toUpperCase();
  }

  function formatRef(ref) {
    return ref && ref.length === 6 ? ref.slice(0, 3) + "-" + ref.slice(3) : ref || "";
  }

  function fail(code, ref, account) {
    finished = true;
    window.clearTimeout(timer);
    var section = document.getElementById("error-" + code) || document.getElementById("error-rejected");
    var reference = section.querySelector("[data-reference]");
    reference.dataset.reference = formatRef(ref);
    reference.querySelector("[data-ref-value]").textContent = (strings.ref || "%s").replace("%s", formatRef(ref));
    reference.hidden = !ref;
    fillIdentity(account);
    show(section.id);
  }

  function complete(data) {
    finished = true;
    fillIdentity(data.account);
    show("success");
    redirectTimer = window.setTimeout(function () {
      window.location.replace(data.redirect);
    }, 1000);
  }

  function schedule() {
    if (finished) {
      return;
    }
    var delay = failures >= 3 ? 5000 : 2000;
    timer = window.setTimeout(poll, delay);
  }

  function poll() {
    if (finished || !statusURL) {
      return;
    }
    var body = new URLSearchParams({flow: flowID, claim: statusToken});
    fetch(statusURL, {method: "POST", headers: {"Content-Type": "application/x-www-form-urlencoded"}, body: body, credentials: "same-origin", cache: "no-store"})
      .then(function (response) {
        return response.json();
      })
      .then(function (data) {
        if (finished) {
          return;
        }
        if (data.expires_at) {
          expiresAt = Date.parse(data.expires_at);
        }
        var unavailable = data.code === "plex_unavailable";
        failures = unavailable ? failures + 1 : 0;
        document.getElementById("unavailable").hidden = failures < 3;
        if (data.status === "complete" && data.redirect) {
          complete(data);
        } else if (data.status === "failed") {
          fail(data.code || "rejected", data.ref, data.account);
        } else {
          schedule();
        }
      })
      .catch(function () {
        failures += 1;
        document.getElementById("unavailable").hidden = failures < 3;
        schedule();
      });
  }

  function pad(n) {
    return n < 10 ? "0" + n : String(n);
  }

  function tick() {
    if (finished || isNaN(expiresAt)) {
      return;
    }
    var left = Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000));
    var text = Math.floor(left / 60) + ":" + pad(left % 60);
    var countdown = document.getElementById("countdown");
    countdown.textContent = (strings.expires || "%s").replace("%s", text);
    if (left <= 60 && !announced) {
      announced = true;
      document.getElementById("countdown-alert").textContent = countdown.textContent;
    }
    if (left === 0) {
      fail("expired");
      if (statusURL) {
        fetch(statusURL, {method: "POST", headers: {"Content-Type": "application/x-www-form-urlencoded"}, body: new URLSearchParams({flow: flowID, claim: statusToken}), credentials: "same-origin", cache: "no-store"}).then(function (response) {
          return response.json();
        }).then(function (data) {
          if (data.code === "expired") fail(data.code, data.ref, data.account);
        }).catch(function () { /* The local expiry still applies when offline. */ });
      }
      return;
    }
    window.setTimeout(tick, 1000);
  }

  document.querySelectorAll("[data-copy]").forEach(function (button) {
    if (!navigator.clipboard) {
      return;
    }
    button.hidden = false;
    var label = button.textContent;
    var reset;
    button.addEventListener("click", function () {
      var ref = button.closest("[data-reference]").dataset.reference;
      navigator.clipboard.writeText(ref).then(function () {
        button.textContent = strings.copied || label;
        window.clearTimeout(reset);
        reset = window.setTimeout(function () {
          button.textContent = label;
        }, 2000);
      }).catch(function () {
        window.getSelection().selectAllChildren(button.previousElementSibling);
      });
    });
  });

  // The first visit immediately opens Plex; returning visits stay here.
  if (root.dataset.autoContinue === "true" && root.dataset.plexUrl) {
    window.location.replace(root.dataset.plexUrl);
    return;
  }

  if (!finished) {
    tick();
    if (root.dataset.screen === "waiting") {
      timer = window.setTimeout(poll, 300);
    }
  }
})();
