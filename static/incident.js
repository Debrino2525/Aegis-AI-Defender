/* Incident Workspace. Renders only fields returned by the console APIs. */
(function () {
  var SEV_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
  var seenCritical = {};
  var state = {
    authed: false,
    monitor: null,
    monitorOk: false,
    scansOk: false,
    alertsOk: false,
    fleetOk: false,
    incidents: [],
    alerts: [],
    scans: [],
    fleetHosts: [],
    scanDetails: {},
    errors: [],
    key: null,
    actionIndex: 0,
    evidenceOpen: true,
    pending: null,
    lastResult: null,
    poll: null,
    busy: false
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

  function ageLabel(iso) {
    if (!iso) return "";
    var t = Date.parse(iso);
    if (isNaN(t)) return String(iso);
    var seconds = Math.max(0, (Date.now() - t) / 1000);
    if (seconds < 60) return Math.floor(seconds) + "s";
    if (seconds < 3600) return Math.floor(seconds / 60) + "m";
    if (seconds < 86400) return Math.floor(seconds / 3600) + "h";
    return Math.floor(seconds / 86400) + "d";
  }

  function list(value) {
    return Array.isArray(value) ? value.filter(function (item) { return item != null && item !== ""; }) : [];
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

  function reasonText(err) {
    if (!err) return "request failed";
    if (err.code) return "HTTP " + err.code;
    return err.message || "request failed";
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

  function isAuth(settled) {
    return settled.status === "rejected" && settled.reason && settled.reason.code === 401;
  }

  function readFocusFromUrl() {
    var q = new URLSearchParams(location.search);
    if (q.get("id")) return "inc:" + q.get("id");
    if (q.get("alert")) return "alert:" + q.get("alert");
    if (q.get("scan")) return "scan:" + q.get("scan");
    return null;
  }

  function writeFocus(key) {
    var url = new URL(location.href);
    url.searchParams.delete("id");
    url.searchParams.delete("alert");
    url.searchParams.delete("scan");
    if (key && key.indexOf("inc:") === 0) url.searchParams.set("id", key.slice(4));
    else if (key && key.indexOf("alert:") === 0) url.searchParams.set("alert", key.slice(6));
    else if (key && key.indexOf("scan:") === 0) url.searchParams.set("scan", key.slice(5));
    history.replaceState(null, "", url);
  }

  function sortedIncidents() {
    return state.incidents.slice().sort(function (a, b) {
      var rank = (SEV_RANK[String(b.severity || "").toUpperCase()] || 0) - (SEV_RANK[String(a.severity || "").toUpperCase()] || 0);
      if (rank) return rank;
      return String(b.last_seen || "").localeCompare(String(a.last_seen || ""));
    });
  }

  function queueItems() {
    var items = [];
    sortedIncidents().forEach(function (inc) {
      items.push({ kind: "inc", key: "inc:" + inc.id, raw: inc });
    });
    state.alerts.forEach(function (alert) {
      var id = alert.alert_id || alert.id;
      if (!id) return;
      items.push({ kind: "alert", key: "alert:" + id, raw: alert });
    });
    state.scans.forEach(function (scan) {
      if (!scan.id) return;
      items.push({ kind: "scan", key: "scan:" + scan.id, raw: scan });
    });
    return items;
  }

  function currentItem() {
    var items = queueItems();
    for (var i = 0; i < items.length; i++) {
      if (items[i].key === state.key) return items[i];
    }
    return null;
  }

  function hostsOf(inc) {
    var set = {};
    list(inc.source_ips).concat(list(inc.dest_ips)).forEach(function (ip) {
      set[String(ip).toLowerCase()] = true;
    });
    return set;
  }

  function hostHit(value, hosts) {
    var text = String(value || "").toLowerCase();
    if (!text) return false;
    if (hosts[text]) return true;
    var bare = text.split(":")[0];
    return !!hosts[bare];
  }

  function matchingScans(inc) {
    var hosts = hostsOf(inc);
    if (!Object.keys(hosts).length) return [];
    return state.scans.filter(function (scan) { return hostHit(scan.target, hosts); });
  }

  async function hydrate() {
    var item = currentItem();
    var wanted = [];
    if (item && item.kind === "inc") {
      matchingScans(item.raw).slice(0, 6).forEach(function (scan) { wanted.push(scan); });
    } else if (item && item.kind === "scan") {
      wanted.push(item.raw);
    } else if (item && item.kind === "alert" && item.raw.source_ip) {
      var ip = String(item.raw.source_ip).toLowerCase();
      state.scans.filter(function (scan) { return hostHit(scan.target, { [ip]: true }); }).slice(0, 4).forEach(function (scan) {
        wanted.push(scan);
      });
    }
    await Promise.all(wanted.map(loadScanDetail));
  }

  async function loadScanDetail(scan) {
    if (!scan || !scan.id) return;
    var sig = [scan.status, scan.total_findings, scan.duration, scan.started_at].join("|");
    var cached = state.scanDetails[scan.id];
    if (cached && cached.sig === sig) return;
    try {
      var body = await getJSON("/api/scans/" + encodeURIComponent(scan.id));
      state.scanDetails[scan.id] = { sig: sig, body: body };
    } catch (err) {
      if (err && err.code === 401) {
        showGate();
        return;
      }
      state.scanDetails[scan.id] = { sig: sig, error: reasonText(err), body: null };
    }
  }

  function statusLine() {
    var parts = [];
    if (!state.monitorOk) parts.push("Monitor unavailable");
    else {
      var running = state.monitor && state.monitor.running;
      var run = running === true ? "Monitor running" : running === false ? "Monitor stopped" : "Monitor";
      parts.push(run + " · " + state.incidents.length + (state.incidents.length === 1 ? " incident" : " incidents"));
    }
    parts.push(state.alertsOk ? (state.alerts.length + " routed alerts") : "Routed alerts unavailable");
    parts.push(state.scansOk ? (state.scans.length + " scans") : "Scans unavailable");
    parts.push(state.fleetOk ? (state.fleetHosts.length + (state.fleetHosts.length === 1 ? " enrolled host" : " enrolled hosts")) : "Fleet unavailable");
    if (state.errors.length) parts.push(state.errors.join(" · "));
    return parts.join(" · ");
  }

  async function loadAll() {
    var settled = await Promise.allSettled([
      getJSON("/api/monitor"),
      getJSON("/api/scans"),
      getJSON("/api/alerting/alerts"),
      getJSON("/api/fleet/hosts")
    ]);
    if (settled.some(isAuth)) {
      showGate();
      return;
    }
    state.errors = [];
    if (settled[0].status === "fulfilled") {
      state.monitorOk = true;
      state.monitor = settled[0].value || {};
      state.incidents = Array.isArray(state.monitor.incidents) ? state.monitor.incidents : [];
    } else {
      state.monitorOk = false;
      state.monitor = null;
      state.incidents = [];
      state.errors.push("Monitor " + reasonText(settled[0].reason));
    }
    if (settled[1].status === "fulfilled") {
      state.scansOk = true;
      state.scans = Array.isArray(settled[1].value) ? settled[1].value : [];
    } else {
      state.scansOk = false;
      state.scans = [];
      state.errors.push("Scans " + reasonText(settled[1].reason));
    }
    if (settled[2].status === "fulfilled") {
      state.alertsOk = true;
      state.alerts = Array.isArray(settled[2].value) ? settled[2].value : [];
    } else {
      state.alertsOk = false;
      state.alerts = [];
      state.errors.push("Alerts " + reasonText(settled[2].reason));
    }
    if (settled[3].status === "fulfilled") {
      state.fleetOk = true;
      var fleetBody = settled[3].value || {};
      state.fleetHosts = Array.isArray(fleetBody.hosts) ? fleetBody.hosts : [];
    } else {
      state.fleetOk = false;
      state.fleetHosts = [];
      state.errors.push("Fleet " + reasonText(settled[3].reason));
    }
    if (!state.key) state.key = readFocusFromUrl();
    if (state.key && state.key.indexOf("inc:") === 0 && !state.incidents.some(function (inc) { return "inc:" + inc.id === state.key; })) {
      var fallback = sortedIncidents()[0];
      if (!readFocusFromUrl()) state.key = fallback ? "inc:" + fallback.id : null;
    }
    if (!state.key) {
      var first = sortedIncidents()[0];
      if (first) state.key = "inc:" + first.id;
      else if (state.alerts[0] && (state.alerts[0].alert_id || state.alerts[0].id)) {
        state.key = "alert:" + (state.alerts[0].alert_id || state.alerts[0].id);
      }
    }
    await hydrate();
    if (!state.authed) return;
    render();
  }

  function render() {
    setStatus(statusLine(), state.errors.length > 0);
    renderQueue();
    renderStory();
    renderDecide();
    $("story").classList.toggle("evidence-collapsed", !state.evidenceOpen);
  }

  function renderQueue() {
    var html = "";
    html += section("Incidents", state.monitorOk, sortedIncidents().map(function (inc) {
      var asset = list(inc.source_ips)[0] || list(inc.dest_ips)[0] || "";
      var bits = [];
      if (asset) bits.push(asset);
      if (inc.alert_count != null) bits.push(inc.alert_count + (inc.alert_count === 1 ? " alert" : " alerts"));
      if (inc.status) bits.push(inc.status);
      var age = ageLabel(inc.last_seen);
      if (age) bits.push(age);
      return itemButton("inc:" + inc.id, sevLabel(inc.severity), inc.id, bits.join(" · "));
    }), "No incidents in the monitor response.");
    html += section("Routed alerts", state.alertsOk, state.alerts.map(function (alert) {
      var id = alert.alert_id || alert.id;
      if (!id) return "";
      var bits = [];
      if (alert.source_ip) bits.push(alert.source_ip);
      if (alert.status) bits.push(alert.status);
      if (alert.acknowledged === 1 || alert.acknowledged === true) bits.push("acked");
      var age = ageLabel(alert.created_at || alert.last_occurrence);
      if (age) bits.push(age);
      return itemButton("alert:" + id, sevLabel(alert.severity), id, bits.join(" · "), alert.title);
    }), "No routed alerts returned.");
    html += section("Scans", state.scansOk, state.scans.map(function (scan) {
      var bits = [];
      if (scan.target) bits.push(scan.target);
      if (scan.status) bits.push(scan.status);
      if (scan.total_findings != null) bits.push(scan.total_findings + " findings");
      return itemButton("scan:" + scan.id, null, scan.id, bits.join(" · "));
    }), "No scans returned.");
    $("queue").innerHTML = html;
  }

  function section(title, ok, rows, empty) {
    var body = rows.filter(Boolean).join("");
    if (!ok) body = '<p class="q-empty">Unavailable.</p>';
    else if (!body) body = '<p class="q-empty">' + esc(empty) + "</p>";
    return '<h3 class="sec-label">' + esc(title) + "</h3>" + body;
  }

  function itemButton(key, severity, id, meta, sub) {
    var current = key === state.key ? ' aria-current="true"' : "";
    var fresh = "";
    if (severity === "CRITICAL" && !seenCritical[key]) {
      seenCritical[key] = true;
      fresh = " is-fresh";
    }
    var sev = severity
      ? '<span class="' + sevClass(severity) + fresh + '">' + esc(severity) + "</span>"
      : "<span></span>";
    return '<button type="button" class="q-item" data-key="' + esc(key) + '"' + current + ">" +
      sev +
      '<span class="q-id">' + esc(id) + "</span>" +
      (sub ? '<span class="q-sub">' + esc(sub) + "</span>" : "") +
      '<span class="q-meta">' + esc(meta) + "</span></button>";
  }

  function renderStory() {
    var item = currentItem();
    var root = $("story-body");
    if (!item) {
      if (state.key && state.key.indexOf("inc:") === 0) {
        root.innerHTML = '<p class="kicker">Incident</p><h2>' + esc(state.key.slice(4)) + "</h2>" +
          '<p class="empty-copy">That id is not in the current monitor response.</p>';
        return;
      }
      root.innerHTML = '<p class="kicker">Incident</p><h2>Nothing selected</h2>' +
        '<p class="empty-copy">Incidents appear when the monitor correlator returns them. Routed alerts and scans stay in the queue only when those APIs return rows.</p>';
      return;
    }
    if (item.kind === "inc") root.innerHTML = incidentStory(item.raw);
    else if (item.kind === "alert") root.innerHTML = alertStory(item.raw);
    else root.innerHTML = scanStory(item.raw);
  }

  function incidentStory(inc) {
    var alerts = list(inc.alerts);
    var html = '<p class="kicker">Incident</p><h2>' + esc(inc.id || "Incident") + "</h2>";
    html += '<div class="chips">';
    if (inc.severity) html += chip(sevLabel(inc.severity));
    if (inc.status) html += chip(inc.status);
    if (inc.urgency) html += chip("Urgency " + inc.urgency);
    if (inc.confidence != null) html += chip("Confidence " + inc.confidence);
    if (inc.alert_count != null) html += chip(inc.alert_count + " alerts");
    html += "</div>";
    if (inc.narrative) {
      html += '<p class="narrative">' + esc(inc.narrative) + "</p>";
      if (alerts.length) html += '<p class="muted">The narrative is correlator text. Each alert below is evidence from this incident.</p>';
    } else {
      html += '<p class="muted">No narrative returned.</p>';
    }
    html += '<div class="block"><h3>Facts</h3><ul class="facts">';
    html += fact("Sources", list(inc.source_ips).join(", "));
    html += fact("Destinations", list(inc.dest_ips).join(", "));
    html += fact("Processes", list(inc.processes).join(", "));
    html += fact("Tactics", list(inc.tactics).join(", "), alerts.length ? "#evidence" : "");
    html += fact("Techniques", list(inc.techniques).join(", "), alerts.length ? "#evidence" : "");
    html += fact("First seen", inc.first_seen);
    html += fact("Last seen", inc.last_seen);
    if (inc.duration_seconds != null) html += fact("Duration", inc.duration_seconds + "s");
    html += "</ul>";
    if (list(inc.source_ips).length) {
      html += '<p class="muted">' + list(inc.source_ips).map(function (ip) {
        return '<a href="/investigate?ip=' + encodeURIComponent(ip) + '">Investigate ' + esc(ip) + "</a>";
      }).join(" · ") + "</p>";
    }
    html += "</div>";
    html += '<div class="block" id="evidence"><h3>Evidence</h3>';
    if (!alerts.length) html += '<p class="muted">No alerts were included on this incident.</p>';
    else {
      html += '<ol class="timeline">';
      alerts.forEach(function (alert, index) {
        html += '<li class="ev" id="ev-' + index + '"><div class="ev-h">';
        if (alert.severity) html += '<span class="' + sevClass(alert.severity) + '">' + esc(sevLabel(alert.severity)) + "</span>";
        html += '<span class="mono">' + esc(alert.id || ("alert " + (index + 1))) + "</span>";
        if (alert.timestamp) html += '<span class="mono">' + esc(alert.timestamp) + "</span>";
        html += '<span class="ev-title">' + esc(alert.title || "Alert") + "</span></div>";
        html += '<div class="ev-body">';
        if (alert.description) html += "<p>" + esc(alert.description) + "</p>";
        var route = [alert.source_ip, alert.dest_ip].filter(Boolean).join(" → ");
        if (alert.dest_port) route += ":" + alert.dest_port;
        if (route) html += '<p class="mono">' + esc(route) + "</p>";
        var tags = [];
        if (alert.pattern_id) tags.push(alert.pattern_id);
        if (alert.tactic) tags.push(alert.tactic);
        if (alert.technique) tags.push(alert.technique);
        if (alert.process) tags.push(alert.process);
        if (tags.length) html += '<p class="mono">' + esc(tags.join(" · ")) + "</p>";
        if (alert.evidence) html += "<p>" + esc(alert.evidence) + "</p>";
        if (alert.acknowledged === false && alert.id) {
          html += '<button type="button" class="btn" data-ack-monitor="' + esc(alert.id) + '">Acknowledge</button>';
        } else if (alert.acknowledged === true) {
          html += '<p class="muted">Acknowledged</p>';
        }
        html += "</div></li>";
      });
      html += "</ol>";
    }
    html += "</div>";
    html += findingsBlock(matchingScans(inc), hostsOf(inc));
    html += fleetBlock(hostsOf(inc));
    return html;
  }

  function alertStory(alert) {
    var id = alert.alert_id || alert.id || "Alert";
    var html = '<p class="kicker">Routed alert</p><h2>' + esc(id) + "</h2>";
    html += '<div class="chips">';
    if (alert.severity) html += chip(sevLabel(alert.severity));
    if (alert.status) html += chip(alert.status);
    if (alert.escalation_level != null) html += chip("Escalation " + alert.escalation_level);
    if (alert.occurrence_count != null) html += chip("Seen " + alert.occurrence_count);
    if (Number(alert.held_count) > 0) html += chip("Held " + alert.held_count);
    html += "</div>";
    if (alert.title) html += '<p class="narrative">' + esc(alert.title) + "</p>";
    html += '<div class="block" id="evidence"><h3>Fields</h3><ul class="facts">';
    ["summary", "source_ip", "dest_ip", "dest_port", "process", "tactic", "technique", "cve_id", "created_at", "last_occurrence", "acknowledged", "acknowledged_by"].forEach(function (key) {
      if (alert[key] != null && alert[key] !== "") html += fact(key, alert[key]);
    });
    html += "</ul></div>";
    if (alert.acknowledged === 0 || alert.acknowledged === false) {
      html += '<button type="button" class="btn" data-ack-routed="' + esc(id) + '">Acknowledge routed alert</button>';
    }
    var hosts = {};
    if (alert.source_ip) hosts[String(alert.source_ip).toLowerCase()] = true;
    var related = state.scans.filter(function (scan) { return hostHit(scan.target, hosts); });
    html += findingsBlock(related, hosts);
    html += fleetBlock(hosts);
    return html;
  }

  function scanStory(scan) {
    var detail = state.scanDetails[scan.id];
    var body = detail && detail.body ? detail.body : scan;
    var html = '<p class="kicker">Scan</p><h2>' + esc(body.id || scan.id) + "</h2>";
    html += '<div class="chips">';
    if (body.target || scan.target) html += chip(body.target || scan.target);
    if (body.status || scan.status) html += chip(body.status || scan.status);
    if ((body.total_findings != null ? body.total_findings : scan.total_findings) != null) {
      html += chip((body.total_findings != null ? body.total_findings : scan.total_findings) + " findings");
    }
    html += "</div>";
    html += '<div class="block"><h3>Scan</h3><ul class="facts">';
    html += fact("Target", body.target || scan.target);
    html += fact("Status", body.status || scan.status);
    html += fact("Started", body.started_at || scan.started_at);
    if (body.duration != null || scan.duration != null) html += fact("Duration", (body.duration != null ? body.duration : scan.duration) + "s");
    var ports = list(body.open_ports);
    if (ports.length) html += fact("Open ports", ports.join(", "));
    var breakdown = body.severity_breakdown || scan.severity_breakdown;
    if (breakdown && typeof breakdown === "object") {
      var parts = Object.keys(breakdown).map(function (key) { return key + " " + breakdown[key]; });
      if (parts.length) html += fact("Severity", parts.join(", "));
    }
    html += "</ul></div>";
    if (detail && detail.error) html += '<p class="muted">Scan detail ' + esc(detail.error) + "</p>";
    var findings = list(body.findings);
    html += '<div class="block" id="evidence"><h3>Findings</h3>';
    html += findingsTable(findings);
    html += "</div>";
    return html;
  }

  function matchingFleet(hosts) {
    return (state.fleetHosts || []).filter(function (row) {
      var keys = [row.hostname, row.agent_id, row.remote_ip]
        .concat(row.ipv4 || [])
        .concat(row.ipv6 || []);
      return keys.some(function (value) { return hostHit(value, hosts); });
    });
  }

  function fleetBlock(hosts) {
    var html = '<div class="block"><h3>Fleet host</h3>';
    if (!state.fleetOk) {
      html += '<p class="muted">Enrolled hosts could not be loaded.</p></div>';
      return html;
    }
    var matched = matchingFleet(hosts);
    if (!matched.length) {
      html += '<p class="muted">No enrolled host matches the addresses on this record.</p></div>';
      return html;
    }
    matched.forEach(function (row) {
      html += '<ul class="facts">';
      html += fact("Hostname", row.hostname);
      html += fact("Agent", row.agent_id);
      html += fact("OS", [row.os_name, row.arch].filter(Boolean).join(" "));
      html += fact("Status", row.status);
      html += fact("Last seen", row.last_seen);
      var addrs = [].concat(row.ipv4 || [], row.ipv6 || []);
      if (addrs.length) html += fact("Addresses", addrs.join(", "));
      if (row.listen_count != null) html += fact("Listening ports", row.listen_count);
      if (row.agent_id) {
        html += '<li><a href="/investigate?host=' + encodeURIComponent(row.agent_id) + '">Open device investigation</a></li>';
      }
      html += "</ul>";
    });
    html += "</div>";
    return html;
  }

  function findingsBlock(scans, hosts) {
    var html = '<div class="block"><h3>Related scan findings</h3>';
    if (!scans.length) {
      html += '<p class="muted">No scan target matches the hosts on this record.</p></div>';
      return html;
    }
    var rows = [];
    scans.forEach(function (scan) {
      var detail = state.scanDetails[scan.id];
      if (!detail) return;
      if (detail.error) {
        rows.push('<p class="muted">' + esc(scan.id) + " " + esc(detail.error) + "</p>");
        return;
      }
      var findings = list(detail.body && detail.body.findings);
      var matched = findings.filter(function (finding) {
        return hostHit(finding.target, hosts) || hostHit(detail.body.target, hosts);
      });
      rows.push('<p class="mono">' + esc(scan.id) + " · " + esc(scan.target || "") + "</p>");
      rows.push(findingsTable(matched));
    });
    html += rows.join("") || '<p class="muted">Scan detail has not loaded.</p>';
    html += "</div>";
    return html;
  }

  function findingsTable(findings) {
    if (!findings.length) return '<p class="muted">No findings on this scan.</p>';
    var html = '<table><thead><tr><th>Severity</th><th>Finding</th><th>Where</th></tr></thead><tbody>';
    findings.slice(0, 20).forEach(function (finding) {
      var where = [finding.target, finding.port].filter(function (part) { return part != null && part !== ""; }).join(":");
      var title = finding.title || finding.id || "Finding";
      if (finding.cve_id) title += " · " + finding.cve_id;
      html += "<tr><td>" + (finding.severity ? '<span class="' + sevClass(finding.severity) + '">' + esc(sevLabel(finding.severity)) + "</span>" : "") + "</td>";
      html += "<td>" + esc(title);
      if (finding.evidence) html += '<div class="finding-evidence">' + esc(finding.evidence) + "</div>";
      html += "</td><td class=\"mono\">" + esc(where) + "</td></tr>";
    });
    html += "</tbody></table>";
    if (findings.length > 20) html += '<p class="muted">Showing 20 of ' + findings.length + " findings returned.</p>";
    return html;
  }

  function chip(text) {
    return '<span class="chip">' + esc(text) + "</span>";
  }

  function fact(label, value, href) {
    if (value == null || value === "") return "";
    var text = esc(value);
    if (!href && String(value).length > 160) {
      return '<li><span class="k">' + esc(label) + '</span><div class="fact-long mono">' + text + "</div></li>";
    }
    var inner = href ? '<a href="' + esc(href) + '">' + text + "</a>" : text;
    return '<li><span class="k">' + esc(label) + "</span> " + inner + "</li>";
  }

  function renderDecide() {
    var item = currentItem();
    var root = $("decide");
    if (!item || item.kind !== "inc") {
      root.innerHTML = '<p class="kicker">Respond</p><h2>No incident selected</h2>' +
        '<p class="empty-copy">Response actions are listed only for an incident the monitor API returns. Routed alerts can be acknowledged from the evidence pane.</p>';
      if (state.lastResult) root.innerHTML += resultBlock(state.lastResult);
      return;
    }
    var inc = item.raw;
    var actions = list(inc.executable_actions);
    var html = '<p class="kicker">Respond</p><h2>' + esc(inc.id || "Incident") + "</h2>";
    html += '<div class="block"><h3>Recommended</h3>';
    var recommended = list(inc.recommended_actions);
    if (!recommended.length) html += '<p class="muted">No recommended actions returned.</p>';
    else {
      html += "<ul>";
      recommended.forEach(function (step) { html += "<li>" + esc(step) + "</li>"; });
      html += "</ul>";
    }
    html += "</div>";
    html += '<div class="block"><h3>Actions</h3>';
    html += '<p class="muted">Review opens a confirm step. Run sends the action to /api/incidents/action.</p>';
    if (!actions.length) html += '<p class="muted">No executable actions returned.</p>';
    actions.forEach(function (action, index) {
      var current = index === state.actionIndex ? ' aria-current="true"' : "";
      html += '<button type="button" class="action' + (action.danger ? " danger" : "") + '" data-action-index="' + index + '"' + current + ">" +
        esc(action.label || action.action || "Action") +
        '<span class="sub">' + esc([action.action, action.target].filter(Boolean).join(" · ")) + "</span></button>";
    });
    html += "</div>";
    var taken = list(inc.actions_taken);
    html += '<div class="block"><h3>Actions taken</h3>';
    if (!taken.length) html += '<p class="muted">None recorded on this incident.</p>';
    else {
      html += '<ul class="log">';
      taken.forEach(function (row) { html += "<li>" + esc(summarizeResult(row)) + "</li>"; });
      html += "</ul>";
    }
    html += "</div>";
    if (state.lastResult) html += resultBlock(state.lastResult);
    root.innerHTML = html;
  }

  function summarizeResult(row) {
    if (!row || typeof row !== "object") return String(row == null ? "" : row);
    var bits = [];
    ["success", "action", "target", "message", "error", "timestamp"].forEach(function (key) {
      if (row[key] != null && row[key] !== "") bits.push(key + ": " + row[key]);
    });
    return bits.join(" · ") || "Action recorded";
  }

  function resultBlock(result) {
    var data = result.data || {};
    return '<div class="block"><h3>Last response</h3><p class="mono">HTTP ' + esc(result.status) + "</p><p>" + esc(summarizeResult(data)) + "</p></div>";
  }

  function openConfirm(index) {
    var item = currentItem();
    if (!item || item.kind !== "inc") return;
    var actions = list(item.raw.executable_actions);
    var action = actions[index];
    if (!action) return;
    state.actionIndex = index;
    state.pending = {
      incidentId: item.raw.id,
      action: action.action,
      target: action.target,
      label: action.label,
      description: action.description,
      danger: !!action.danger
    };
    $("confirm-title").textContent = action.label || "Review action";
    var facts = "";
    [["Action", action.action], ["Target", action.target], ["Incident", item.raw.id], ["What it does", action.description]].forEach(function (pair) {
      if (pair[1] == null || pair[1] === "") return;
      facts += "<dt>" + esc(pair[0]) + "</dt><dd>" + esc(pair[1]) + "</dd>";
    });
    $("confirm-facts").innerHTML = facts;
    $("confirm-check").checked = false;
    $("confirm-run").disabled = true;
    $("confirm-run").className = action.danger ? "btn btn-danger" : "btn btn-primary";
    renderDecide();
    $("confirm").showModal();
  }

  async function runPending() {
    if (!state.pending || state.busy || !$("confirm-check").checked) return;
    state.busy = true;
    $("confirm-run").disabled = true;
    var pending = state.pending;
    try {
      var res = await fetch("/api/incidents/action", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          incident_id: pending.incidentId,
          action_type: pending.action,
          target: pending.target
        })
      });
      var data = {};
      try { data = await res.json(); } catch (e) {}
      if (res.status === 401) {
        showGate();
        return;
      }
      state.lastResult = { status: res.status, data: data };
      state.pending = null;
      $("confirm").close();
      await loadAll();
    } finally {
      state.busy = false;
    }
  }

  async function ack(url) {
    var res = await fetch(url, { method: "POST", credentials: "same-origin" });
    if (res.status === 401) {
      showGate();
      return;
    }
    var data = {};
    try { data = await res.json(); } catch (e) {}
    state.lastResult = { status: res.status, data: data };
    await loadAll();
  }

  function move(delta) {
    var items = queueItems();
    if (!items.length) return;
    var index = 0;
    items.forEach(function (item, i) { if (item.key === state.key) index = i; });
    index = Math.max(0, Math.min(items.length - 1, index + delta));
    choose(items[index].key);
  }

  function choose(key) {
    state.key = key;
    state.actionIndex = 0;
    writeFocus(key);
    hydrate().then(function () { if (state.authed) render(); });
  }

  function onKey(event) {
    if (!state.authed) return;
    var tag = (event.target && event.target.tagName) || "";
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
    if ($("confirm").open) return;
    if (event.key === "j" || event.key === "J") { event.preventDefault(); move(1); }
    else if (event.key === "k" || event.key === "K") { event.preventDefault(); move(-1); }
    else if (event.key === "e" || event.key === "E") {
      event.preventDefault();
      state.evidenceOpen = !state.evidenceOpen;
      render();
    } else if (event.key === "c" || event.key === "C") {
      event.preventDefault();
      openConfirm(state.actionIndex || 0);
    }
  }

  function startPoll() {
    stopPoll();
    state.poll = setInterval(function () {
      if (!state.authed || document.hidden || $("confirm").open) return;
      loadAll();
    }, 8000);
  }

  function stopPoll() {
    if (state.poll) clearInterval(state.poll);
    state.poll = null;
  }

  document.addEventListener("click", function (event) {
    var keyBtn = event.target.closest("[data-key]");
    if (keyBtn) {
      choose(keyBtn.getAttribute("data-key"));
      return;
    }
    var actionBtn = event.target.closest("[data-action-index]");
    if (actionBtn) {
      openConfirm(Number(actionBtn.getAttribute("data-action-index")));
      return;
    }
    var mon = event.target.closest("[data-ack-monitor]");
    if (mon) {
      ack("/api/monitor/alerts/" + encodeURIComponent(mon.getAttribute("data-ack-monitor")) + "/ack");
      return;
    }
    var routed = event.target.closest("[data-ack-routed]");
    if (routed) ack("/api/alerting/alerts/" + encodeURIComponent(routed.getAttribute("data-ack-routed")) + "/ack");
  });

  document.addEventListener("keydown", onKey);

  $("confirm-check").addEventListener("change", function () {
    $("confirm-run").disabled = !eventTargetChecked();
  });

  function eventTargetChecked() {
    return $("confirm-check").checked;
  }

  $("confirm-cancel").addEventListener("click", function () {
    state.pending = null;
    $("confirm").close();
  });
  $("confirm-run").addEventListener("click", runPending);
  $("confirm").addEventListener("cancel", function () { state.pending = null; });

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
