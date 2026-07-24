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

  // Deletes are irreversible: confirm first. Delegated so cards inserted by
  // the live poll are covered too. (Attached here because CSP blocks inline
  // onsubmit handlers.)
  document.addEventListener("submit", function (e) {
    var form = e.target;
    if (form.classList.contains("delete-invalid")) {
      var n = form.getAttribute("data-count") || "all";
      if (!window.confirm("Delete " + n + " submission(s) with unresolvable email addresses? This cannot be undone.")) {
        e.preventDefault();
      }
    } else if (form.classList.contains("delete-submission")) {
      var id = form.getAttribute("data-id") || "";
      if (!window.confirm("Permanently delete submission #" + id + "? Unlike archiving, this cannot be undone.")) {
        e.preventDefault();
      }
    }
  });

  // ---- Unsaved-edit guard ---------------------------------------------------
  // A card's comment/status edits sit in a form the operator must Save; any
  // navigation or other action while edits are pending would silently discard
  // them. So: pending edits mark their card dirty. Acting anywhere else —
  // following a link, submitting another form, changing the status filter —
  // is blocked, and the dirty card turns red (and scrolls into view) until
  // the edit is saved or undone. Focus merely leaving a dirty card turns it
  // red too, so a half-finished edit can't quietly disappear from attention.

  function fieldDefault(el) {
    if (el.tagName === "SELECT") {
      for (var i = 0; i < el.options.length; i++) {
        if (el.options[i].defaultSelected) return el.options[i].value;
      }
      return el.options.length ? el.options[0].value : "";
    }
    return el.defaultValue;
  }

  // Recomputes a status form's dirty state from its editable fields and
  // reflects it on the card. Undoing an edit back to the stored value clears
  // both the dirty state and any red flag.
  function refreshDirty(form) {
    var card = form.closest(".card");
    if (!card) return;
    var fields = form.querySelectorAll("textarea[name=comment], select[name=status]");
    var dirty = false;
    for (var i = 0; i < fields.length; i++) {
      var d = fields[i].value !== fieldDefault(fields[i]);
      fields[i].classList.toggle("dirty-field", d);
      if (d) dirty = true;
    }
    if (dirty) {
      card.classList.add("dirty");
    } else {
      card.classList.remove("dirty", "unsaved");
    }
  }

  function dirtyCards() {
    return document.querySelectorAll(".card.dirty");
  }

  // Turns every dirty card red and brings the first one into view. Returns
  // whether anything was flagged (i.e. the triggering action was blocked).
  function flagUnsaved() {
    var cards = dirtyCards();
    for (var i = 0; i < cards.length; i++) cards[i].classList.add("unsaved");
    if (cards.length) cards[0].scrollIntoView({ behavior: "smooth", block: "center" });
    return cards.length > 0;
  }

  document.addEventListener("input", function (e) {
    var form = e.target.closest && e.target.closest("form.status-form");
    if (form) refreshDirty(form);
  });
  document.addEventListener("change", function (e) {
    var form = e.target.closest && e.target.closest("form.status-form");
    if (form) refreshDirty(form);
  });

  // Focus leaving a dirty card (to another card, the filter, anywhere) flags
  // it red immediately.
  document.addEventListener("focusout", function (e) {
    var card = e.target.closest && e.target.closest(".card.dirty");
    if (card && (!e.relatedTarget || !card.contains(e.relatedTarget))) {
      card.classList.add("unsaved");
    }
  });

  // Any link is navigation; with pending edits it is blocked outright.
  document.addEventListener("click", function (e) {
    if (e.defaultPrevented) return;
    var link = e.target.closest && e.target.closest("a[href]");
    if (link && dirtyCards().length) {
      e.preventDefault();
      flagUnsaved();
    }
  }, true);

  // Submits: saving (or deliberately deleting) the dirty card itself is the
  // way out and always allowed — but only when it is the ONLY dirty card,
  // because the resulting page load would discard every other pending edit.
  // Capture phase so the block runs before the delete-confirm prompt below.
  var saving = false;
  document.addEventListener("submit", function (e) {
    var ownCard = e.target.closest ? e.target.closest(".card") : null;
    var cards = dirtyCards();
    for (var i = 0; i < cards.length; i++) {
      if (cards[i] !== ownCard) {
        e.preventDefault();
        e.stopPropagation();
        flagUnsaved();
        return;
      }
    }
    // Allowed submit: suppress the leave-page prompt for its navigation.
    saving = true;
    setTimeout(function () { saving = false; }, 2000);
  }, true);

  // Backstop for navigation the handlers above can't see (back button, typed
  // URL, tab close): the browser's own are-you-sure prompt.
  window.addEventListener("beforeunload", function (e) {
    if (!saving && dirtyCards().length) {
      e.preventDefault();
      e.returnValue = "";
    }
  });

  // ---- Status filter: apply on change ---------------------------------------
  // Picking a status IS the intent; the Apply button only exists for JS-off
  // browsers. Blocked (and reverted) while a card holds unsaved edits.
  var filter = document.querySelector("form.filter");
  if (filter) {
    var filterSelect = filter.querySelector("select[name=status]");
    var filterButton = filter.querySelector("button");
    if (filterSelect) {
      if (filterButton) filterButton.hidden = true;
      filterSelect.setAttribute("data-prev", filterSelect.value);
      filterSelect.addEventListener("change", function () {
        if (dirtyCards().length) {
          filterSelect.value = filterSelect.getAttribute("data-prev");
          flagUnsaved();
          return;
        }
        // submit() skips the submit-event guard; dirty state was checked.
        filter.submit();
      });
    }
  }

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
        // A full batch means more submissions are waiting beyond the new
        // cursor: follow up almost immediately until caught up.
        interval = data.more ? 300 : baseInterval;
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
    // Dedupe by submission id: the page render and the first poll can
    // legitimately overlap (a row inserted while the dashboard was being
    // built appears in both), and dropping the copy here is what makes that
    // overlap harmless.
    var cards = tmp.querySelectorAll(".card");
    for (var i = 0; i < cards.length; i++) {
      var sid = cards[i].getAttribute("data-submission-id");
      if (sid && section.querySelector('.card[data-submission-id="' + sid + '"]')) {
        cards[i].remove();
      } else {
        cards[i].classList.add("live-new");
      }
    }
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
