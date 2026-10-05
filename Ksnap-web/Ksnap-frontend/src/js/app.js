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
  // the default store and every folder a dump was written to
  directories: [],
  // where the last dump went, offered again in the next one
  lastDirectory: null,
  // the snapshot the delete dialog is asking about
  pendingDelete: null,
};

// how a verdict from the backend is shown in the Status column
const LEVELS = {
  ok: { label: "restorable", className: "text-bg-success" },
  risky: { label: "partial", className: "text-bg-warning" },
  blocked: { label: "not restorable", className: "text-bg-danger" },
  unknown: { label: "not checked", className: "text-bg-secondary" },
};

const dumpModal = new bootstrap.Modal("#dump-modal");
const deleteModal = new bootstrap.Modal("#delete-modal");
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

// .exe-path cuts long paths on the left with direction: rtl, the marks keep the
// leading "/" where it belongs instead of letting the bidi rules move it
function pathText(path) {
  return `\u200e${path}\u200e`;
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

// one colored dot, a count and a label per verdict, the kernel threads that
// are left out of the list sit apart on the right
function renderProcessSummary() {
  const footer = element("process-summary");
  footer.innerHTML = "";

  for (const level of ["ok", "risky", "blocked", "unknown"]) {
    const count = state.counts[level] || 0;
    if (level === "unknown" && !count) continue;

    const item = document.createElement("span");
    item.className = "summary-item";
    const dot = document.createElement("span");
    dot.className = `summary-dot ${LEVELS[level].className.replace("text-bg-", "bg-")}`;
    const number = document.createElement("span");
    number.className = "fw-semibold";
    number.textContent = count;
    const label = document.createElement("span");
    label.className = "text-secondary";
    label.textContent = LEVELS[level].label;
    item.append(dot, number, label);
    footer.appendChild(item);
  }

  if (state.kernelThreads) {
    const hidden = document.createElement("span");
    hidden.className = "text-secondary ms-auto";
    hidden.textContent = `${state.kernelThreads} kernel ${
      state.kernelThreads === 1 ? "thread" : "threads"
    } hidden`;
    footer.appendChild(hidden);
  }
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

function renderSnapshots(snapshots, directories) {
  const footer = element("snapshot-dir");
  footer.textContent =
    directories.length === 1 ? directories[0] : `${directories.length} folders`;
  footer.title = directories.join("\n");
  const tbody = element("snapshot-rows");

  if (!snapshots.length) {
    placeholder(tbody, 5, "No snapshot yet, pick a process and create one.");
    return;
  }

  tbody.innerHTML = "";
  // with one folder the table stays flat, with more each folder gets a header
  const grouped = directories.length > 1;
  for (const directory of directories) {
    const inFolder = snapshots.filter((snapshot) => snapshot.directory === directory);
    if (!inFolder.length) continue;

    if (grouped) {
      const header = tbody.insertRow();
      header.className = "snapshot-group";
      const td = header.insertCell();
      td.colSpan = 5;
      const path = document.createElement("span");
      path.className = "exe-path snapshot-group-path";
      path.textContent = pathText(directory);
      path.title = directory;
      td.appendChild(path);
    }

    for (const snapshot of inFolder) renderSnapshotRow(tbody, snapshot);
  }
}

function renderSnapshotRow(tbody, snapshot) {
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
    path.textContent = pathText(snapshot.exe_path);
    path.title =
      `${snapshot.exe_path}\nRIP ${snapshot.rip}  RSP ${snapshot.rsp}` +
      `\nFPU/SSE/AVX state ${snapshot.xstate_size} B`;
    executable.appendChild(path);
    cell(row, snapshot.vma_count, "text-end");
  }

  cell(row, formatSize(snapshot.size), "text-end text-nowrap");

  const actions = row.insertCell();
  actions.className = "text-end text-nowrap";

  if (!snapshot.error) {
    const restore = document.createElement("button");
    restore.className = "btn btn-sm btn-success me-1";
    restore.textContent = "Restore";
    restore.dataset.restoreButton = "true";
    restore.disabled = state.restoreRunning;
    restore.addEventListener("click", () =>
      restoreSnapshot(snapshot.name, snapshot.directory),
    );
    actions.appendChild(restore);
  }

  const remove = document.createElement("button");
  remove.className = "btn btn-sm btn-outline-danger";
  remove.textContent = "Delete";
  remove.addEventListener("click", () =>
    openDeleteModal(snapshot),
  );
  actions.appendChild(remove);
}

async function refreshSnapshots() {
  try {
    const payload = await api("/api/snapshots");
    state.directories = payload.directories;
    renderSnapshots(payload.snapshots, payload.directories);
  } catch (error) {
    showError(error);
  }
}

async function restoreSnapshot(name, directory) {
  try {
    await api("/api/restore", {
      method: "POST",
      body: JSON.stringify({ name, directory }),
    });
    await refreshStatus();
  } catch (error) {
    showError(error);
  }
}

function openDeleteModal(snapshot) {
  state.pendingDelete = snapshot;
  element("delete-name").textContent = snapshot.name;
  element("delete-size").textContent = formatSize(snapshot.size);
  const directory = element("delete-directory");
  directory.textContent = pathText(snapshot.directory || "");
  directory.title = snapshot.directory || "";
  deleteModal.show();
}

async function deleteSnapshot() {
  const snapshot = state.pendingDelete;
  if (!snapshot) return;

  const button = element("delete-submit");
  button.disabled = true;
  try {
    const name = encodeURIComponent(snapshot.name);
    const folder = encodeURIComponent(snapshot.directory || "");
    await api(`/api/snapshots/${name}?directory=${folder}`, { method: "DELETE" });
    // cleared only on success, after a failure the dialog stays usable
    state.pendingDelete = null;
    deleteModal.hide();
    await refreshSnapshots();
  } catch (error) {
    showError(error);
  } finally {
    button.disabled = false;
  }
}

/* ------------------------------------------------------------------ dump  */

function openDumpModal() {
  const process = state.processes.find((item) => item.pid === state.selectedPid);
  if (!process) return;

  const bytes = (process.eligibility.facts || {}).snapshot_bytes;
  element("dump-target-name").textContent = process.name;
  element("dump-target-pid").textContent = `PID ${process.pid}`;
  const command = element("dump-target-command");
  command.textContent = process.cmdline;
  command.title = process.cmdline;
  command.classList.toggle("d-none", !process.cmdline);
  element("dump-target-size").textContent = bytes ? formatSize(bytes) : "";
  element("dump-target-size-row").classList.toggle("d-none", !bytes);
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
    const { title, detail } = describeCaveat(caveat, process.eligibility.facts || {});
    const item = document.createElement("li");
    const name = document.createElement("div");
    name.className = "dump-caveat-title";
    name.textContent = title;
    const text = document.createElement("div");
    text.className = "dump-caveat-detail";
    text.textContent = detail;
    item.append(name, text);
    list.appendChild(item);
  }
  element("dump-warning").classList.toggle("d-none", caveats.length === 0);
  element("dump-directory").value = state.lastDirectory || state.directories[0] || "";
  const options = element("dump-directory-options");
  options.innerHTML = "";
  for (const directory of state.directories) {
    const option = document.createElement("option");
    option.value = directory;
    options.appendChild(option);
  }
  // ending a process is never remembered from the previous dump
  element("dump-kill").checked = false;
  updateDumpSubmit();
  dumpModal.show();
}

function plural(count, singular, pluralForm) {
  return `${count} ${count === 1 ? singular : pluralForm}`;
}

// a short title and one line of detail per caveat, built from the facts where
// the panel knows them, the backend message is the fallback for the rest
function describeCaveat(caveat, facts) {
  switch (caveat.code) {
    case "arguments_not_restored":
      return { title: "Command line arguments", detail: "The process restarts without them" };
    case "open_files": {
      const volatile = facts.volatile_fds || 0;
      const files = (facts.open_fds || 0) - volatile;
      const parts = [];
      if (volatile) parts.push(plural(volatile, "socket or pipe", "sockets or pipes"));
      if (files > 0) parts.push(plural(files, "file", "files"));
      return { title: "Open descriptors", detail: parts.join(", ") || caveat.message };
    }
    case "has_children":
      return {
        title: "Child processes",
        detail: plural(facts.children || 0, "child process", "child processes"),
      };
    case "large_snapshot":
      return { title: "Large snapshot", detail: capitalize(caveat.message) };
    case "path_with_space":
      return { title: "Executable path", detail: "Contains a space, which the engine truncates" };
    default:
      return { title: capitalize(caveat.code.replace(/_/g, " ")), detail: capitalize(caveat.message) };
  }
}

function capitalize(text) {
  return text ? text[0].toUpperCase() + text.slice(1) : text;
}

function updateDumpSubmit() {
  const kill = element("dump-kill").checked;
  const button = element("dump-submit");
  button.textContent = kill ? "Snapshot and terminate" : "Snapshot";
  button.classList.toggle("btn-primary", !kill);
  button.classList.toggle("btn-danger", kill);
}

async function submitDump(event) {
  event.preventDefault();
  const button = element("dump-submit");
  const kill = element("dump-kill").checked;
  const directory = element("dump-directory").value.trim();
  button.disabled = true;
  try {
    await api("/api/dump", {
      method: "POST",
      body: JSON.stringify({
        pid: state.selectedPid,
        name: element("dump-name").value.trim(),
        directory,
        kill,
      }),
    });
    state.lastDirectory = directory;
    dumpModal.hide();
    await refreshSnapshots();
    // the process is gone, the list must not offer it any more
    if (kill) await refreshProcesses();
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
  element("dump-kill").addEventListener("change", updateDumpSubmit);
  element("delete-submit").addEventListener("click", deleteSnapshot);
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
