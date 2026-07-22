// Live dashboard updates. The submissions section carries data-poll-url,
// data-latest (highest submission id in the whole table at render time), and
// data-status (the active filter). Every few seconds we ask the server for
// anything newer; matching cards come back as server-rendered HTML fragments
// and are prepended in place — no reload. Polling pauses while the tab is
// hidden, backs off after repeated errors (daemon restart, network blip), and
// stops for good when the session expires (401/redirect) — logging back in
// reloads the page anyway.
(function () {
  "use strict";

  var section = document.querySelector(".submissions[data-poll-url]");
  if (!section || !window.fetch) return;

  var pollURL = section.getAttribute("data-poll-url");
  var after = parseInt(section.getAttribute("data-latest") || "0", 10) || 0;
  var status = section.getAttribute("data-status") || "";
  var baseInterval = 7000;
  var interval = baseInterval;
  var failures = 0;
  var timer = null;
  var inFlight = false;
  var stopped = false;

  function schedule() {
    if (stopped) return;
    if (timer) clearTimeout(timer);
    timer = setTimeout(poll, interval);
  }

  function poll() {
    if (stopped || inFlight) return;
    if (document.hidden) {
      schedule();
      return;
    }
    inFlight = true;
    var url = pollURL + "?after=" + after;
    if (status) url += "&status=" + encodeURIComponent(status);
    fetch(url, { credentials: "same-origin", headers: { Accept: "application/json" } })
      .then(function (resp) {
        // An expired session redirects to the login page: stop polling.
        if (resp.status === 401 || resp.status === 403 || resp.redirected) throw "auth";
        if (!resp.ok) throw "http";
        var ct = resp.headers.get("Content-Type") || "";
        if (ct.indexOf("application/json") === -1) throw "auth";
        return resp.json();
      })
      .then(function (data) {
        failures = 0;
        interval = baseInterval;
        if (data.latest > after) after = data.latest;
        if (data.html) insert(data.html);
      })
      .catch(function (err) {
        if (err === "auth") {
          stopped = true;
          return;
        }
        failures++;
        interval = Math.min(baseInterval * Math.pow(2, failures), 60000);
      })
      .then(function () {
        inFlight = false;
        schedule();
      });
  }

  function insert(html) {
    var empty = section.querySelector(".empty-note");
    if (empty) empty.remove();
    var tmp = document.createElement("div");
    tmp.innerHTML = html;
    var cards = tmp.querySelectorAll(".card");
    for (var i = 0; i < cards.length; i++) cards[i].classList.add("live-new");
    // Fragment is newest-first; inserting from the last child up keeps that
    // order once everything sits above the existing cards.
    while (tmp.lastElementChild) {
      section.insertBefore(tmp.lastElementChild, section.firstChild);
    }
  }

  document.addEventListener("visibilitychange", function () {
    if (!document.hidden && !stopped) {
      interval = baseInterval;
      if (timer) clearTimeout(timer);
      poll();
    }
  });

  schedule();
})();
