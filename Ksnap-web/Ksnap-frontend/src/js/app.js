/*
 * Ksnap panel.
 *
 * Everything the page shows comes from the Flask API in Ksnap-backend:
 * the process list, the snapshot store, the restore session and the console
 * feed, which is polled incrementally with a sequence cursor.
 */
"use strict";

const POLL_INTERVAL_MS = 1000;

const state = {
  processes: [],
  counts: { ok: 0, risky: 0, blocked: 0 },
  kernelThreads: 0,
  selectedPid: null,
  logCursor: 0,
  restoreRunning: false,
};

// how a verdict from the backend is shown in the Status column
const LEVELS = {
  ok: { label: "restorable", className: "text-bg-success" },
  risky: { label: "partial", className: "text-bg-warning" },
  blocked: { label: "not restorable", className: "text-bg-danger" },
  unknown: { label: "not checked", className: "text-bg-secondary" },
};

const dumpModal = new bootstrap.Modal("#dump-modal");
const element = (id) => document.getElementById(id);

/* ---------------------------------------------------------------- helpers */

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || `request failed (${response.status})`);
  }
  return payload;
}

function showError(error) {
  const alert = document.createElement("div");
  alert.className = "alert alert-danger alert-dismissible fade show";
  alert.innerHTML =
    '<span class="me-2"></span>' +
    '<button type="button" class="btn-close" data-bs-dismiss="alert"></button>';
  alert.firstChild.textContent = error.message || String(error);
  element("alerts").prepend(alert);
  setTimeout(() => bootstrap.Alert.getOrCreateInstance(alert).close(), 8000);
}

function formatSize(bytes) {
  if (!bytes) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), 3);
  return `${(bytes / 1024 ** index).toFixed(index ? 1 : 0)} ${units[index]}`;
}

function formatTime(iso) {
  return iso ? new Date(iso).toLocaleString() : "-";
}

function cell(row, text, className) {
  const td = row.insertCell();
  if (className) td.className = className;
  td.textContent = text;
  return td;
}

function badge(row, level, reasons) {
  const td = row.insertCell();
  const span = document.createElement("span");
  span.className = `badge ${LEVELS[level].className}`;
  span.textContent = reasons.length ? reasons[0].code.replace(/_/g, " ") : LEVELS[level].label;
  td.title = reasons.map((reason) => reason.message).join("\n") || "the engine handles this process";
  td.appendChild(span);
  return td;
}

function placeholder(tbody, columns, text) {
  tbody.innerHTML = "";
  const row = tbody.insertRow();
  const td = row.insertCell();
  td.colSpan = columns;
  td.className = "text-secondary p-3";
  td.textContent = text;
}

/* --------------------------------------------------------------- statuses */

function renderStatus(status) {
  const engine = element("pill-engine");
  engine.textContent = status.engine_present ? "engine ready" : "engine missing";
  engine.className = `badge ${status.engine_present ? "text-bg-success" : "text-bg-danger"}`;

  const privileges = element("pill-privileges");
  privileges.textContent = status.root
    ? "running as root"
    : status.sudo
      ? "sudo -n"
      : "unprivileged";
  privileges.className = `badge ${status.root || status.sudo ? "text-bg-secondary" : "text-bg-warning"}`;

  const restore = element("pill-restore");
  state.restoreRunning = Boolean(status.restore && status.restore.running);
  restore.textContent = state.restoreRunning
    ? `restoring ${status.restore.snapshot}`
    : "idle";
  restore.className = `badge ${state.restoreRunning ? "text-bg-info" : "text-bg-secondary"}`;

  element("btn-stop").classList.toggle("d-none", !state.restoreRunning);
  document
    .querySelectorAll("[data-restore-button]")
    .forEach((button) => (button.disabled = state.restoreRunning));
}

async function refreshStatus() {
  try {
    renderStatus(await api("/api/status"));
  } catch (error) {
    showError(error);
  }
}

/* -------------------------------------------------------------- processes */

function renderProcesses(processes) {
  const tbody = element("process-rows");
  if (!processes.length) {
    placeholder(tbody, 8, "No process the engine can restore. Tick 'Show all' to see why.");
    renderProcessSummary();
    return;
  }

  tbody.innerHTML = "";
  for (const process of processes) {
    const row = tbody.insertRow();
    row.dataset.pid = String(process.pid);

    const level = process.eligibility.level;
    const blocked = level === "blocked" || level === "unknown";
    if (blocked) row.className = "opacity-50";

    const radio = document.createElement("input");
    radio.type = "radio";
    radio.name = "process";
    radio.className = "form-check-input";
    radio.checked = process.pid === state.selectedPid;
    radio.disabled = blocked;
    radio.addEventListener("change", () => selectProcess(process.pid));
    row.insertCell().appendChild(radio);
    if (!blocked) {
      row.addEventListener("click", () => {
        radio.checked = true;
        selectProcess(process.pid);
      });
    }

    cell(row, process.pid, "font-monospace");
    const name = cell(row, process.name);
    name.title = process.cmdline;
    cell(row, process.user);

    cell(row, process.threads, "text-end");
    badge(row, level, process.eligibility.reasons);
    cell(row, formatSize(process.rss_kb * 1024), "text-end");
    cell(row, process.state, "text-secondary");
  }

  renderProcessSummary();
}

function renderProcessSummary() {
  const { ok, risky, blocked, unknown } = state.counts;
  const skipped = state.kernelThreads
    ? `, ${state.kernelThreads} kernel thread(s) skipped`
    : "";
  const unchecked = unknown ? `, ${unknown} not checked` : "";
  element("process-summary").textContent =
    `${ok} restorable, ${risky} partial, ${blocked} not restorable` +
    `${unchecked}${skipped}`;
}

function selectProcess(pid) {
  const process = state.processes.find((item) => item.pid === pid);
  state.selectedPid = process ? pid : null;
  const level = process ? process.eligibility.level : "unknown";
  element("btn-dump").disabled = level === "blocked" || level === "unknown";
}

async function refreshProcesses() {
  try {
    const query = element("process-filter").value.trim();
    const all = element("process-show-all").checked ? "1" : "";
    const payload = await api(
      `/api/processes?query=${encodeURIComponent(query)}&all=${all}`,
    );
    state.processes = payload.processes;
    state.counts = payload.counts;
    state.kernelThreads = payload.kernel_threads;
    if (!state.processes.some((process) => process.pid === state.selectedPid)) {
      state.selectedPid = null;
      element("btn-dump").disabled = true;
    }
    renderProcesses(state.processes);
  } catch (error) {
    showError(error);
  }
}

/* -------------------------------------------------------------- snapshots */

function renderSnapshots(snapshots, directory) {
  element("snapshot-dir").textContent = directory;
  const tbody = element("snapshot-rows");

  if (!snapshots.length) {
    placeholder(tbody, 5, "No snapshot yet, pick a process and create one.");
    return;
  }

  tbody.innerHTML = "";
  for (const snapshot of snapshots) {
    const row = tbody.insertRow();
    const name = cell(row, snapshot.name, "font-monospace");
    name.title = `created ${formatTime(snapshot.created_at)}`;

    if (snapshot.error) {
      const problem = cell(row, snapshot.error, "text-danger small");
      problem.colSpan = 2;
    } else {
      const executable = row.insertCell();
      const path = document.createElement("span");
      path.className = "exe-path";
      path.textContent = snapshot.exe_path;
      path.title = `${snapshot.exe_path}\nRIP ${snapshot.rip}  RSP ${snapshot.rsp}`;
      executable.appendChild(path);
      cell(row, snapshot.vma_count, "text-end");
    }

    cell(row, formatSize(snapshot.size), "text-end");

    const actions = row.insertCell();
    actions.className = "text-end text-nowrap";

    if (!snapshot.error) {
      const restore = document.createElement("button");
      restore.className = "btn btn-sm btn-success me-1";
      restore.textContent = "Restore";
      restore.dataset.restoreButton = "true";
      restore.disabled = state.restoreRunning;
      restore.addEventListener("click", () => restoreSnapshot(snapshot.name));
      actions.appendChild(restore);
    }

    const remove = document.createElement("button");
    remove.className = "btn btn-sm btn-outline-danger";
    remove.textContent = "Delete";
    remove.addEventListener("click", () => deleteSnapshot(snapshot.name));
    actions.appendChild(remove);
  }
}

async function refreshSnapshots() {
  try {
    const payload = await api("/api/snapshots");
    renderSnapshots(payload.snapshots, payload.directory);
  } catch (error) {
    showError(error);
  }
}

async function restoreSnapshot(name) {
  try {
    await api("/api/restore", { method: "POST", body: JSON.stringify({ name }) });
    await refreshStatus();
  } catch (error) {
    showError(error);
  }
}

async function deleteSnapshot(name) {
  if (!confirm(`Delete snapshot ${name}?`)) return;
  try {
    await api(`/api/snapshots/${encodeURIComponent(name)}`, { method: "DELETE" });
    await refreshSnapshots();
  } catch (error) {
    showError(error);
  }
}

/* ------------------------------------------------------------------ dump  */

function openDumpModal() {
  const process = state.processes.find((item) => item.pid === state.selectedPid);
  if (!process) return;

  const bytes = (process.eligibility.facts || {}).snapshot_bytes;
  const size = bytes ? ` | snapshot about ${formatSize(bytes)}` : "";
  element("dump-target").textContent =
    `${process.name} (pid ${process.pid}): ${process.cmdline}${size}`;
  element("dump-name").value = `${process.name}-${process.pid}`.replace(
    /[^A-Za-z0-9._-]/g,
    "-",
  );
  const caveats = process.eligibility.reasons.filter(
    (reason) => reason.level === "risky",
  );
  const list = element("dump-warning-list");
  list.innerHTML = "";
  for (const caveat of caveats) {
    const item = document.createElement("li");
    item.textContent = caveat.message;
    list.appendChild(item);
  }
  element("dump-warning").classList.toggle("d-none", caveats.length === 0);
  dumpModal.show();
}

async function submitDump(event) {
  event.preventDefault();
  const button = element("dump-submit");
  button.disabled = true;
  try {
    await api("/api/dump", {
      method: "POST",
      body: JSON.stringify({
        pid: state.selectedPid,
        name: element("dump-name").value.trim(),
      }),
    });
    dumpModal.hide();
    await refreshSnapshots();
  } catch (error) {
    showError(error);
  } finally {
    button.disabled = false;
  }
}

/* ---------------------------------------------------------------- console */

function appendLogs(entries) {
  const console_ = element("console");
  const empty = console_.querySelector(".console-empty");
  if (empty) empty.remove();

  for (const entry of entries) {
    const line = document.createElement("div");
    line.className = "console-line";
    line.dataset.level = entry.level;

    const time = document.createElement("span");
    time.className = "console-time";
    time.textContent = new Date(entry.ts).toLocaleTimeString();

    const source = document.createElement("span");
    source.className = "console-source";
    source.textContent = entry.source;

    const text = document.createElement("span");
    text.className = "console-text";
    text.textContent = entry.message;

    line.append(time, source, text);
    console_.appendChild(line);
  }

  if (entries.length && element("autoscroll").checked) {
    console_.scrollTop = console_.scrollHeight;
  }
}

async function pollLogs() {
  try {
    const payload = await api(`/api/logs?since=${state.logCursor}`);
    state.logCursor = payload.cursor;
    appendLogs(payload.entries);
  } catch (error) {
    /* the console keeps its content, the next tick retries */
  }
}

async function clearLogs() {
  try {
    await api("/api/logs", { method: "DELETE" });
    element("console").innerHTML =
      '<div class="console-empty">Console cleared.</div>';
  } catch (error) {
    showError(error);
  }
}

/* ------------------------------------------------------------------- boot */

function bind() {
  element("btn-refresh-processes").addEventListener("click", refreshProcesses);
  element("btn-refresh-snapshots").addEventListener("click", refreshSnapshots);
  element("btn-dump").addEventListener("click", openDumpModal);
  element("dump-form").addEventListener("submit", submitDump);
  element("btn-clear-logs").addEventListener("click", clearLogs);
  element("btn-stop").addEventListener("click", async () => {
    try {
      await api("/api/restore/stop", { method: "POST" });
      await refreshStatus();
    } catch (error) {
      showError(error);
    }
  });

  element("process-show-all").addEventListener("change", refreshProcesses);

  let filterTimer;
  element("process-filter").addEventListener("input", () => {
    clearTimeout(filterTimer);
    filterTimer = setTimeout(refreshProcesses, 250);
  });
}

element("console").innerHTML = '<div class="console-empty">Waiting for events…</div>';
bind();
refreshStatus();
refreshProcesses();
refreshSnapshots();

setInterval(pollLogs, POLL_INTERVAL_MS);
setInterval(refreshStatus, 2000);
