/* Device investigation. Renders only the investigation object from the console API. */
(function () {
  var SEV_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
  var state = {
    authed: false,
    rows: [],
    current: null,
    key: null,
    errors: [],
    preview: null,
    poll: null,
    busy: false,
    evidenceOpen: true
  };

  function $(id) { return document.getElementById(id); }

  function esc(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function sevClass(severity) {
    var s = String(severity || "INFO").toUpperCase();
    if (!SEV_RANK.hasOwnProperty(s)) s = "INFO";
    return "sev sev-" + s.toLowerCase();
  }

  function sevLabel(severity) {
    var s = String(severity || "").toUpperCase();
    return SEV_RANK.hasOwnProperty(s) ? s : (s || "UNKNOWN");
  }

  function showGate() {
    state.authed = false;
    $("gate").hidden = false;
    $("workspace").hidden = true;
    $("lock-btn").hidden = true;
    setStatus("Session locked");
    var field = $("unlock-secret");
    if (field) field.focus();
  }

  function showApp() {
    state.authed = true;
    $("gate").hidden = true;
    $("workspace").hidden = false;
    $("lock-btn").hidden = false;
  }

  function setStatus(text, bad) {
    var el = $("status");
    el.textContent = text;
    el.className = bad ? "status bad" : "status";
  }

  async function getJSON(url) {
    var res = await fetch(url, { credentials: "same-origin" });
    if (res.status === 401) {
      var authErr = new Error("auth");
      authErr.code = 401;
      throw authErr;
    }
    if (!res.ok) {
      var err = new Error(url);
      err.code = res.status;
      throw err;
    }
    return res.json();
  }

  function readFocusFromUrl() {
    var q = new URLSearchParams(location.search);
    if (q.get("id")) return q.get("id");
    if (q.get("host")) return "host:" + q.get("host");
    if (q.get("ip")) return "ip:" + q.get("ip");
    return null;
  }

  function writeFocus(key) {
    var url = new URL(location.href);
    url.searchParams.delete("id");
    url.searchParams.delete("host");
    url.searchParams.delete("ip");
    if (!key) {
      history.replaceState(null, "", url);
      return;
    }
    if (key.indexOf("host:") === 0) url.searchParams.set("host", key.slice(5));
    else if (key.indexOf("ip:") === 0) url.searchParams.set("ip", key.slice(3));
    else url.searchParams.set("id", key);
    history.replaceState(null, "", url);
  }

  function detailUrl(key) {
    if (key && key.indexOf("host:") === 0) {
      return "/api/investigations?host=" + encodeURIComponent(key.slice(5));
    }
    if (key && key.indexOf("ip:") === 0) {
      return "/api/investigations?ip=" + encodeURIComponent(key.slice(3));
    }
    return "/api/investigations?id=" + encodeURIComponent(key || "");
  }

  async function loadAll() {
    try {
      var listed = await getJSON("/api/investigations");
      state.rows = Array.isArray(listed.investigations) ? listed.investigations : [];
      state.errors = [];
    } catch (err) {
      if (err && err.code === 401) {
        showGate();
        return;
      }
      state.rows = [];
      state.errors = ["Investigations " + ((err && err.code) ? ("HTTP " + err.code) : "unavailable")];
    }
    if (!state.key) state.key = readFocusFromUrl();
    if (state.key && !state.rows.some(function (row) { return row.id === state.key; })) {
      if (!readFocusFromUrl() && state.rows[0]) state.key = state.rows[0].id;
    }
    if (!state.key && state.rows[0]) state.key = state.rows[0].id;
    await loadCurrent();
    if (!state.authed) return;
    render();
  }

  async function loadCurrent() {
    if (!state.key) {
      state.current = null;
      return;
    }
    try {
      state.current = await getJSON(detailUrl(state.key));
    } catch (err) {
      if (err && err.code === 401) {
        showGate();
        return;
      }
      if (err && err.code === 404) {
        state.current = null;
        return;
      }
      state.errors.push("Detail " + ((err && err.code) ? ("HTTP " + err.code) : "unavailable"));
      state.current = null;
    }
  }

  function render() {
    var n = state.rows.length;
    var line = n + (n === 1 ? " device" : " devices");
    if (state.errors.length) line += " · " + state.errors.join(" · ");
    setStatus(line, state.errors.length > 0);
    renderQueue();
    renderStory();
    renderDecide();
    $("story").classList.toggle("evidence-collapsed", !state.evidenceOpen);
  }

  function renderQueue() {
    var enrolled = state.rows.filter(function (row) { return row.kind === "enrolled_host"; });
    var ips = state.rows.filter(function (row) { return row.kind !== "enrolled_host"; });
    var html = "";
    html += section("Enrolled hosts", enrolled, "No enrolled host has heartbeated.");
    html += section("Source IPs", ips, "No source IP appears in monitor, alert, or scan samples.");
    $("queue").innerHTML = html;
  }

  function section(title, rows, empty) {
    var body = rows.map(itemButton).join("");
    if (!body) body = '<p class="q-empty">' + esc(empty) + "</p>";
    return '<h3 class="sec-label">' + esc(title) + "</h3>" + body;
  }

  function itemButton(row) {
    var current = row.id === state.key ? ' aria-current="true"' : "";
    var bits = [];
    if (row.addresses && row.addresses.length) bits.push(row.addresses[0]);
    if (row.status) bits.push(row.status);
    if (row.alert_count) bits.push(row.alert_count + (row.alert_count === 1 ? " alert" : " alerts"));
    if (row.socket_count) bits.push(row.socket_count + (row.socket_count === 1 ? " socket" : " sockets"));
    if (row.finding_count) bits.push(row.finding_count + (row.finding_count === 1 ? " finding" : " findings"));
    if (row.kev_count) bits.push(row.kev_count + " KEV");
    return '<button type="button" class="q-item" data-key="' + esc(row.id) + '"' + current + ">" +
      "<span></span>" +
      '<span class="q-id">' + esc(row.label || row.id) + "</span>" +
      '<span class="q-meta">' + esc(bits.join(" · ")) + "</span></button>";
  }

  function renderStory() {
    var root = $("story-body");
    var inv = state.current;
    if (!inv) {
      if (state.key) {
        root.innerHTML = '<p class="kicker">Device</p><h2>' + esc(state.key) + "</h2>" +
          '<p class="empty-copy">No enrolled host or source IP matches that key in the current monitor, fleet, or scan data.</p>';
        return;
      }
      root.innerHTML = '<p class="kicker">Device</p><h2>Nothing selected</h2>' +
        '<p class="empty-copy">Open an enrolled host or a source IP. The timeline only lists samples the monitor, agent, or scanner actually returned.</p>';
      return;
    }
    var device = inv.device || {};
    var html = '<p class="kicker">' + esc(device.kind === "enrolled_host" ? "Enrolled host" : "Source IP") + "</p>";
    html += "<h2>" + esc(device.hostname || (device.addresses || [])[0] || inv.id) + "</h2>";
    html += '<div class="chips">';
    if (device.agent_id) html += chip(device.agent_id);
    if (device.status) html += chip(device.status);
    if (device.os_name) html += chip([device.os_name, device.arch].filter(Boolean).join(" "));
    (device.addresses || []).slice(0, 4).forEach(function (addr) { html += chip(addr); });
    html += "</div>";
    if (device.sample) {
      html += '<p class="muted">Identity is the last agent heartbeat <a class="sample-link" href="#sample-' +
        esc(device.sample.id) + '">' + esc(device.sample.id) + "</a>.</p>";
    }
    html += postureBlock(device.posture);
    html += assistBlock(inv.analyst_assist || inv);
    html += '<div class="block" id="evidence"><h3>Evidence timeline</h3>';
    var timeline = inv.timeline || [];
    if (!timeline.length) {
      html += '<p class="muted">No samples yet for this host.</p>';
    } else {
      html += '<ol class="timeline">';
      timeline.forEach(function (item) {
        html += '<li class="ev" id="sample-' + esc(item.id) + '"><div class="ev-h">';
        html += '<span class="kind">' + esc(item.kind || "sample") + "</span>";
        if (item.ts) html += '<span class="mono">' + esc(item.ts) + "</span>";
        html += '<span class="ev-title">' + esc(item.title || item.id) + "</span></div>";
        html += '<div class="ev-body">';
        if (item.detail) html += "<p>" + esc(item.detail) + "</p>";
        html += '<p class="mono">sample ' + esc(item.id) + "</p>";
        html += sampleFields(item.sample);
        html += "</div></li>";
      });
      html += "</ol>";
    }
    html += "</div>";
    html += '<div class="block"><h3>Related alerts</h3>';
    var related = inv.related_alerts || [];
    if (!related.length) html += '<p class="muted">None on this host in the current queues.</p>';
    else {
      related.forEach(function (alert) {
        html += '<p>' + (alert.severity ? '<span class="' + sevClass(alert.severity) + '">' + esc(sevLabel(alert.severity)) + "</span> " : "") +
          '<a class="sample-link" href="#sample-' + esc(alert.id) + '">' + esc(alert.id) + "</a> " +
          esc(alert.title || "") +
          (alert.pattern_id ? ' <span class="mono">' + esc(alert.pattern_id) + "</span>" : "") +
          "</p>";
      });
    }
    html += "</div>";
    var gaps = inv.gaps || [];
    if (gaps.length) {
      html += '<div class="block"><h3>Gaps</h3>';
      gaps.forEach(function (gap) { html += '<p class="gap">' + esc(gap) + "</p>"; });
      html += "</div>";
    }
    root.innerHTML = html;
  }

  function sampleFields(sample) {
    if (!sample || typeof sample !== "object") return "";
    var skip = { kind: 1, id: 1 };
    var html = '<ul class="facts">';
    Object.keys(sample).forEach(function (key) {
      if (skip[key]) return;
      var value = sample[key];
      if (value == null || value === "" || (Array.isArray(value) && !value.length)) return;
      if (typeof value === "object") value = JSON.stringify(value);
      html += '<li><span class="k">' + esc(key) + "</span> " + esc(value) + "</li>";
    });
    html += "</ul>";
    return html;
  }

  function list(value) {
    return Array.isArray(value) ? value.filter(function (item) { return item != null && item !== ""; }) : [];
  }

  function assistBlock(assist) {
    if (!assist) return "";
    var groups = list(assist.groups);
    var phases = list(assist.phases);
    var hops = list(assist.hops);
    var related = list(assist.related_detections);
    var html = '<div class="block"><h3>Analyst Assist</h3>';
    html += '<p class="assist-note">Grouped by host, time, and tactic. Phases and hops appear only when a sample exists.</p>';
    if (!groups.length && !phases.length && !hops.length && !related.length) {
      html += '<p class="muted">No grouped detections on this host yet.</p>';
      list(assist.gaps).forEach(function (gap) { html += '<p class="gap">' + esc(gap) + "</p>"; });
      html += "</div>";
      return html;
    }
    if (groups.length) {
      html += "<h3>Groups</h3>";
      groups.forEach(function (group) {
        html += '<div class="group-row"><div class="g-h">';
        html += '<span class="chip">' + esc(group.tactic || "Ungrouped") + "</span>";
        html += '<span class="mono">' + esc(group.host || "") + "</span>";
        html += "</div>";
        list(group.pattern_ids).forEach(function (pid) {
          html += '<span class="chip">' + esc(pid) + "</span>";
        });
        list(group.evidence).forEach(function (item) {
          html += '<p class="related-row"><a class="sample-link" href="#sample-' + esc(item.sample_id || item.alert_id || "") + '">' +
            esc(item.alert_id || item.sample_id || "") + "</a> " + esc(item.title || "") + "</p>";
        });
        html += "</div>";
      });
    }
    if (phases.length) {
      html += '<h3>Phases</h3><div class="phase-list">';
      phases.forEach(function (phase, index) {
        if (index) html += '<span class="phase-arrow">→</span>';
        html += '<span class="phase">' + esc(phase.phase) + " · " + esc((phase.tactics || []).join(", ")) + "</span>";
      });
      html += "</div>";
    }
    if (hops.length) {
      html += "<h3>Observed hops</h3>";
      hops.forEach(function (hop) {
        html += '<div class="hop-path">';
        list(hop.path).forEach(function (node, index) {
          if (index) {
            var edge = (hop.edges || [])[index - 1] || {};
            html += '<span class="hop-edge">' + esc((edge.protocol || "") + ":" + (edge.port || "") + " →") + "</span>";
          }
          html += '<span class="hop-node">' + esc(node) + "</span>";
        });
        html += "</div>";
        list(hop.edges).forEach(function (edge) {
          html += '<p class="related-row"><a class="sample-link" href="#sample-' + esc(edge.sample_id || "") + '">' +
            esc(edge.sample_id || "") + "</a> " + esc(edge.protocol || "") + " " +
            esc(edge.src || "") + " → " + esc(edge.dst || "") + ":" + esc(edge.port || "") + "</p>";
        });
      });
    }
    if (related.length) {
      html += "<h3>Related detections</h3>";
      related.forEach(function (row) {
        html += '<p class="related-row"><span class="mono">' + esc(row.pattern_id || "") + "</span> " +
          esc(row.title || "") + "</p>";
      });
    }
    html += "</div>";
    return html;
  }

  function chip(text) {
    return '<span class="chip">' + esc(text) + "</span>";
  }

  function postureBlock(posture) {
    var html = '<div class="block" id="posture"><h3>Prevent posture</h3>';
    if (!posture) {
      html += '<p class="muted">No posture object on this device.</p></div>';
      return html;
    }
    var n = posture.finding_count || 0;
    var breakdown = posture.severity_breakdown || {};
    if (!n) {
      html += '<p class="muted">' + esc(posture.empty_reason || "0 findings on last scan") + "</p></div>";
      return html;
    }
    html += '<div class="chips">';
    html += chip(n + (n === 1 ? " finding" : " findings"));
    if (breakdown.CRITICAL) html += chip(breakdown.CRITICAL + " critical");
    if (breakdown.HIGH) html += chip(breakdown.HIGH + " high");
    if (posture.kev_count) html += chip(posture.kev_count + " KEV");
    if (posture.risk_label) html += chip("risk " + posture.risk_label);
    html += "</div>";
    var cves = list(posture.cves);
    if (cves.length) {
      html += "<h3>CVEs on this host</h3>";
      cves.forEach(function (cve) {
        html += '<p class="related-row"><span class="mono">' + esc(cve.cve_id) + "</span> " +
          (cve.severity ? '<span class="' + sevClass(cve.severity) + '">' + esc(sevLabel(cve.severity)) + "</span> " : "") +
          esc(cve.title || "") +
          (cve.scan_id ? ' <span class="mono">' + esc(cve.scan_id) + "</span>" : "") +
          "</p>";
      });
    }
    var findings = list(posture.findings);
    if (findings.length) {
      html += "<h3>Findings</h3>";
      findings.forEach(function (finding) {
        html += '<p class="related-row">' +
          (finding.severity ? '<span class="' + sevClass(finding.severity) + '">' + esc(sevLabel(finding.severity)) + "</span> " : "") +
          '<a class="sample-link" href="#sample-' + esc((finding.scan_id || "") + ":" + (finding.id || "")) + '">' +
          esc(finding.id || "") + "</a> " + esc(finding.title || "") + "</p>";
      });
    }
    html += "</div>";
    return html;
  }

  function renderDecide() {
    var root = $("decide");
    var inv = state.current;
    if (!inv) {
      root.innerHTML = '<p class="kicker">Respond</p><h2>No device selected</h2>' +
        '<p class="empty-copy">Contain dry-run is listed only when a socket or alert sample names an address or process.</p>';
      return;
    }
    var html = '<p class="kicker">Claims</p><h2>' + esc(inv.id) + "</h2>";
    var claims = inv.claims || [];
    if (!claims.length) html += '<p class="muted">No evidence-linked claims.</p>';
    claims.forEach(function (claim) {
      html += '<div class="claim"><p>' + esc(claim.text) + "</p>" +
        '<a class="sample-link" href="#sample-' + esc(claim.sample_id) + '">' + esc(claim.sample_id) + "</a></div>";
    });
    html += '<div class="block"><h3>Contain dry-run</h3>';
    html += '<p class="dry-note">' + esc((inv.contain && inv.contain.scope) || "Dry-run only. Nothing is executed.") + "</p>";
    var actions = (inv.contain && inv.contain.actions) || [];
    if (!actions.length) html += '<p class="muted">No dry-run actions. Need a socket or alert sample.</p>';
    actions.forEach(function (action, index) {
      if (!action.success) return;
      html += '<button type="button" class="action" data-preview-index="' + index + '">' +
        esc(action.label || action.action) +
        '<span class="sub">' + esc([action.action, action.target].filter(Boolean).join(" · ")) +
        (action.evidence_sample_id ? " · sample " + action.evidence_sample_id : "") +
        "</span></button>";
    });
    html += "</div>";
    if (state.preview) {
      html += '<div class="preview"><h3>Dry-run result</h3>';
      html += "<p>" + esc(state.preview.would || state.preview.error || "Preview returned.") + "</p>";
      html += '<p class="mono">mutates: ' + esc(String(state.preview.mutates)) +
        " · dry_run: " + esc(String(state.preview.dry_run)) + "</p>";
      if (state.preview.evidence_sample_id) {
        html += '<p><a class="sample-link" href="#sample-' + esc(state.preview.evidence_sample_id) + '">' +
          esc(state.preview.evidence_sample_id) + "</a></p>";
      }
      var cmds = state.preview.commands || [];
      if (cmds.length) html += "<pre>" + esc(cmds.join("\n")) + "</pre>";
      html += "</div>";
    }
    root.innerHTML = html;
  }

  async function runPreview(index) {
    var inv = state.current;
    if (!inv || state.busy) return;
    var action = ((inv.contain && inv.contain.actions) || [])[index];
    if (!action) return;
    state.busy = true;
    try {
      var res = await fetch("/api/investigations/" + encodeURIComponent(inv.id) + "/contain", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action: action.action,
          target: action.target,
          dry_run: true
        })
      });
      if (res.status === 401) {
        showGate();
        return;
      }
      var data = {};
      try { data = await res.json(); } catch (e) {}
      state.preview = data;
      renderDecide();
    } finally {
      state.busy = false;
    }
  }

  function choose(key) {
    state.key = key;
    state.preview = null;
    writeFocus(key);
    loadCurrent().then(function () { if (state.authed) render(); });
  }

  function move(delta) {
    if (!state.rows.length) return;
    var index = 0;
    state.rows.forEach(function (row, i) { if (row.id === state.key) index = i; });
    index = Math.max(0, Math.min(state.rows.length - 1, index + delta));
    choose(state.rows[index].id);
  }

  function onKey(event) {
    if (!state.authed) return;
    var tag = (event.target && event.target.tagName) || "";
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
    if (event.key === "j" || event.key === "J") { event.preventDefault(); move(1); }
    else if (event.key === "k" || event.key === "K") { event.preventDefault(); move(-1); }
    else if (event.key === "e" || event.key === "E") {
      event.preventDefault();
      state.evidenceOpen = !state.evidenceOpen;
      render();
    } else if (event.key === "c" || event.key === "C") {
      event.preventDefault();
      runPreview(0);
    }
  }

  function startPoll() {
    stopPoll();
    state.poll = setInterval(function () {
      if (!state.authed || document.hidden) return;
      loadAll();
    }, 8000);
  }

  function stopPoll() {
    if (state.poll) clearInterval(state.poll);
    state.poll = null;
  }

  document.addEventListener("click", function (event) {
    var link = event.target.closest(".sample-link");
    if (link && link.getAttribute("href") && link.getAttribute("href").indexOf("#sample-") === 0) {
      var target = document.getElementById(link.getAttribute("href").slice(1));
      if (target) {
        event.preventDefault();
        document.querySelectorAll(".ev.is-target").forEach(function (el) { el.classList.remove("is-target"); });
        target.classList.add("is-target");
        target.scrollIntoView({ block: "center" });
      }
      return;
    }
    var keyBtn = event.target.closest("[data-key]");
    if (keyBtn) {
      choose(keyBtn.getAttribute("data-key"));
      return;
    }
    var previewBtn = event.target.closest("[data-preview-index]");
    if (previewBtn) runPreview(Number(previewBtn.getAttribute("data-preview-index")));
  });

  document.addEventListener("keydown", onKey);

  $("unlock-form").addEventListener("submit", async function (event) {
    event.preventDefault();
    var secret = ($("unlock-secret").value || "").trim();
    var err = $("unlock-err");
    err.textContent = "";
    try {
      var res = await fetch("/api/auth/login", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ secret: secret })
      });
      if (!res.ok) {
        err.textContent = "That token or password was not accepted.";
        return;
      }
      $("unlock-secret").value = "";
      showApp();
      await loadAll();
      startPoll();
    } catch (e) {
      err.textContent = "Could not reach the console.";
    }
  });

  $("lock-btn").addEventListener("click", async function () {
    stopPoll();
    try { await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" }); } catch (e) {}
    showGate();
  });

  document.addEventListener("visibilitychange", function () {
    if (!state.authed) return;
    if (document.hidden) stopPoll();
    else { loadAll(); startPoll(); }
  });

  async function boot() {
    try {
      var res = await fetch("/api/auth/status", { credentials: "same-origin" });
      var data = await res.json();
      if (!data.authenticated) {
        showGate();
        return;
      }
      showApp();
      state.key = readFocusFromUrl();
      await loadAll();
      startPoll();
    } catch (e) {
      setStatus("Could not reach the console", true);
      showGate();
    }
  }

  boot();
})();
