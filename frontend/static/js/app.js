const DB_KEY = "malwareDetectionHistory_v1";

function loadHistory() {
  try {
    return JSON.parse(localStorage.getItem(DB_KEY) || "[]");
  } catch {
    return [];
  }
}

function saveHistory(items) {
  localStorage.setItem(DB_KEY, JSON.stringify(items));
}

function fileSize(bytes) {
  if (!Number.isFinite(bytes)) return "—";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  let n = bytes;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(i ? 2 : 0)} ${units[i]}`;
}

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[char]));
}

function predictionBadge(prediction) {
  const className = prediction === "Malware" ? "badge-danger" : "badge-success";
  return `<span class="badge ${className}">${esc(prediction)}</span>`;
}

function modelCard(title, result, thresholdLabel) {
  const isMalware = result.prediction === "Malware";
  const statusClass = isMalware ? "model-malware" : "model-benign";
  return `
    <article class="panel model-result-card ${statusClass}">
      <div class="model-result-heading">
        <div>
          <div class="kicker">Machine learning model</div>
          <h3>${esc(title)}</h3>
        </div>
        ${predictionBadge(result.prediction)}
      </div>
      <div class="model-probability">
        <span class="model-probability-value">${(result.maliciousProbability * 100).toFixed(2)}%</span>
        <span class="muted">Malicious probability</span>
      </div>
      <div class="model-result-details">
        <div><span>Prediction confidence</span><strong>${(result.confidence * 100).toFixed(2)}%</strong></div>
        <div><span>Decision threshold</span><strong>${(result.threshold * 100).toFixed(0)}%</strong></div>
      </div>
      <div class="probability-track" role="progressbar"
           aria-label="${esc(title)} malicious probability"
           aria-valuemin="0" aria-valuemax="100"
           aria-valuenow="${(result.maliciousProbability * 100).toFixed(2)}">
        <span style="width:${Math.max(0, Math.min(100, result.maliciousProbability * 100))}%"></span>
      </div>
    </article>`;
}

function setupScanner() {
  const input = document.querySelector("#fileInput");
  if (!input) return;

  const drop = document.querySelector("#dropzone");
  const pick = document.querySelector("#pickBtn");
  const preview = document.querySelector("#filePreview");
  const nameEl = document.querySelector("#fileName");
  const sizeEl = document.querySelector("#fileSize");
  const scanBtn = document.querySelector("#scanBtn");
  const clearBtn = document.querySelector("#clearBtn");
  const status = document.querySelector("#uploadStatus");
  const scanForm = document.querySelector("#scanForm");
  const analysisPanel = document.querySelector("#analysisProgress");
  const analysisFileName = document.querySelector("#analysisFileName");
  const analysisMessage = document.querySelector("#analysisMessage");
  const progressLabel = document.querySelector("#analysisProgressLabel");
  const progressTrack = document.querySelector("#analysisProgressBar");
  const progressFill = progressTrack?.querySelector(".progress-fill");
  const steps = [...document.querySelectorAll("[data-analysis-step]")];
  let selectedFile = null;

  function setProgress(completedCount, percent, message) {
    steps.forEach((step, index) => {
      const complete = index < completedCount;
      const active = index === completedCount;
      step.dataset.state = complete ? "complete" : active ? "active" : "queued";
      const state = step.querySelector(".step-state");
      if (state) state.textContent = complete ? "Complete" : active ? "In progress" : "Queued";
      if (active) step.setAttribute("aria-current", "step");
      else step.removeAttribute("aria-current");
    });
    if (progressFill) progressFill.style.width = `${percent}%`;
    progressTrack?.setAttribute("aria-valuenow", String(percent));
    if (progressLabel) progressLabel.textContent = `${String(percent).padStart(2, "0")}%`;
    if (analysisMessage) analysisMessage.textContent = message;
  }

  function acceptFile(file) {
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".exe")) {
      status.dataset.state = "error";
      status.textContent = "Please select a Windows .exe file.";
      selectedFile = null;
      preview.classList.add("hidden");
      input.value = "";
      return;
    }
    if (file.size > 100 * 1024 * 1024) {
      status.dataset.state = "error";
      status.textContent = "File exceeds the 100 MB upload limit.";
      selectedFile = null;
      preview.classList.add("hidden");
      input.value = "";
      return;
    }
    selectedFile = file;
    nameEl.textContent = file.name;
    sizeEl.textContent = fileSize(file.size);
    preview.classList.remove("hidden");
    status.dataset.state = "ready";
    status.textContent = "File ready. Both models will analyse the same static features.";
  }

  pick?.addEventListener("click", () => input.click());
  input.addEventListener("change", event => acceptFile(event.target.files?.[0]));

  ["dragenter", "dragover"].forEach(type => drop?.addEventListener(type, event => {
    event.preventDefault();
    drop.classList.add("dragover");
  }));
  ["dragleave", "drop"].forEach(type => drop?.addEventListener(type, event => {
    event.preventDefault();
    drop.classList.remove("dragover");
  }));
  drop?.addEventListener("drop", event => acceptFile(event.dataTransfer.files?.[0]));

  clearBtn?.addEventListener("click", () => {
    selectedFile = null;
    input.value = "";
    preview.classList.add("hidden");
    delete status.dataset.state;
    status.textContent = "No file selected.";
  });

  scanBtn?.addEventListener("click", async () => {
    if (!selectedFile) {
      status.dataset.state = "error";
      status.textContent = "Please select an .exe file first.";
      return;
    }

    const fileBeingScanned = selectedFile;
    scanBtn.disabled = true;
    scanBtn.textContent = "Analyzing...";
    scanBtn.setAttribute("aria-busy", "true");
    status.dataset.state = "busy";
    status.textContent = "Sending file for static analysis...";
    if (analysisFileName) analysisFileName.textContent = fileBeingScanned.name;
    scanForm.classList.add("hidden");
    analysisPanel.classList.remove("hidden");

    try {
      setProgress(0, 10, "Validating the uploaded executable...");
      const formData = new FormData();
      formData.append("file", fileBeingScanned);

      setProgress(1, 30, "Extracting the 2,381 EMBER v2 static features...");
      const response = await fetch("/api/scan", { method: "POST", body: formData });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "Analysis failed.");

      setProgress(2, 75, "Running Random Forest and LightGBM predictions...");
      if (!result.models?.randomForest || !result.models?.lightGBM) {
        throw new Error("The server returned incomplete model results.");
      }

      const history = loadHistory();
      history.unshift(result);
      saveHistory(history.slice(0, 50));
      setProgress(steps.length, 100, "Both model predictions are ready. Opening results...");
      window.location.href = `results.html?id=${encodeURIComponent(result.id)}`;
    } catch (error) {
      console.error("Scan error:", error);
      analysisPanel.classList.add("hidden");
      scanForm.classList.remove("hidden");
      status.dataset.state = "error";
      status.textContent = error.message || "Unable to analyse file.";
      scanBtn.disabled = false;
      scanBtn.textContent = "Analyze with both models";
      scanBtn.removeAttribute("aria-busy");
    }
  });
}

function setupResults() {
  const root = document.querySelector("#resultRoot");
  if (!root) return;

  const id = new URLSearchParams(location.search).get("id");
  const history = loadHistory();
  const item = history.find(entry => entry.id === id) || history[0];

  if (!item) {
    root.innerHTML = `
      <div class="panel scan-card empty-state">
        <div class="upload-icon" aria-hidden="true">?</div>
        <h2>No scan result found</h2>
        <p>Upload a Windows executable to generate a new analysis.</p>
        <a class="btn btn-primary" href="scan.html">Start a scan</a>
      </div>`;
    return;
  }

  const models = item.models;
  if (!models?.randomForest || !models?.lightGBM) {
    root.innerHTML = `
      <div class="panel scan-card">
        <h2>Older scan record</h2>
        <p>This result was saved by an earlier single-model version of StaticShield. Scan the file again to compare both models.</p>
        <a class="btn btn-primary" href="scan.html">Run a new scan</a>
      </div>`;
    return;
  }

  const agreement = item.modelsAgree;
  const statusText = agreement
    ? `Both models agree: ${item.overallPrediction}.`
    : "The models produced different classifications. Review both predictions below.";
  const statusClass = agreement
    ? (item.overallPrediction === "Malware" ? "badge-danger" : "badge-success")
    : "badge-neutral";

  root.innerHTML = `
    <section class="panel scan-card result-file-panel">
      <div class="result-file-heading">
        <div>
          <div class="kicker">Analysed executable</div>
          <h2>${esc(item.fileName)}</h2>
          <p class="muted">${fileSize(item.fileSize)} · ${esc(item.fileType)} · ${new Date(item.uploadedAt).toLocaleString()}</p>
        </div>
        <span class="badge badge-neutral">Static analysis</span>
      </div>
      <div class="result-overall">
        <div>
          <div class="kicker">Model comparison</div>
          <strong>${esc(statusText)}</strong>
        </div>
        <span class="badge ${statusClass}">${agreement ? esc(item.overallPrediction.toUpperCase()) : "DISAGREEMENT"}</span>
      </div>
    </section>

    <section class="model-comparison-grid" aria-label="Independent model predictions">
      ${modelCard("Random Forest", models.randomForest)}
      ${modelCard("LightGBM", models.lightGBM)}
    </section>

    <section class="panel scan-card result-explanation">
      <div class="section-head">
        <div><h2>Understanding the results</h2><p>Each classifier makes its own prediction using the same extracted EMBER features.</p></div>
      </div>
      <div class="result-info">
        <div class="stat"><label>Feature set</label><strong>EMBER v2 · 2,381 features</strong></div>
        <div class="stat"><label>Random Forest threshold</label><strong>50%</strong></div>
        <div class="stat"><label>LightGBM threshold</label><strong>52%</strong></div>
        <div class="stat"><label>Models' agreement</label><strong>${agreement ? "Yes" : "No"}</strong></div>
      </div>
      <p class="notice">${esc(item.note || "A benign classification does not guarantee that a file is safe.")}</p>
      <p class="analysis-footnote">Malicious probability is the model's estimated probability for the malware class. Prediction confidence refers to the probability of the class selected by that model. These values are not a guarantee of file safety.</p>
    </section>`;
}

function setupHistory() {
  const body = document.querySelector("#historyBody");
  if (!body) return;
  const history = loadHistory();

  if (!history.length) {
    body.innerHTML = `
      <div class="panel scan-card empty-state">
        <div class="upload-icon" aria-hidden="true">↗</div>
        <h3>No scans yet</h3>
        <p>Your scan records will appear here after an executable is analysed.</p>
        <a class="btn btn-primary" href="scan.html">Scan a file</a>
      </div>`;
    return;
  }

  body.innerHTML = `<div class="history-list">${history.map(item => {
    const hasTwoModels = Boolean(item.models?.randomForest && item.models?.lightGBM);
    const summary = hasTwoModels
      ? (item.modelsAgree ? `Both: ${item.overallPrediction}` : "Model disagreement")
      : (item.prediction || "Older scan");
    const isMalware = summary.includes("Malware");
    const badgeClass = summary === "Model disagreement" ? "badge-neutral"
      : isMalware ? "badge-danger" : "badge-success";
    return `
      <a class="history-row" href="results.html?id=${encodeURIComponent(item.id)}">
        <div><strong>${esc(item.fileName)}</strong><div class="muted">${esc(item.fileType || "PE Executable")}</div></div>
        <div><span class="badge ${badgeClass}">${esc(summary)}</span></div>
        <div class="hide-md muted">${fileSize(item.fileSize)}</div>
        <div class="hide-md muted">${new Date(item.uploadedAt).toLocaleString()}</div>
        <div class="badge badge-neutral">${hasTwoModels ? "2 models" : esc(item.algorithm || "Legacy")}</div>
      </a>`;
  }).join("")}</div>`;
}

document.addEventListener("DOMContentLoaded", () => {
  setupScanner();
  setupResults();
  setupHistory();
});
