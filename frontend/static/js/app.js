const DB_KEY = "malwareDetectionHistory_v1";

function loadHistory() {
  try { return JSON.parse(localStorage.getItem(DB_KEY) || "[]"); }
  catch { return []; }
}
function saveHistory(items) { localStorage.setItem(DB_KEY, JSON.stringify(items)); }

function fileSize(bytes) {
  if (!Number.isFinite(bytes)) return "—";
  const units = ["B","KB","MB","GB"];
  let i = 0, n = bytes;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 2 : 0)} ${units[i]}`;
}
function esc(v) {
  return String(v).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function setupScanner() {
  const input = document.querySelector("#fileInput");
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
  const analysisProgressLabel = document.querySelector("#analysisProgressLabel");
  const progressTrack = document.querySelector("#analysisProgressBar");
  const progressFill = progressTrack?.querySelector(".progress-fill");
  const analysisSteps = [...document.querySelectorAll("[data-analysis-step]")];

  if (!input) return;

  let selectedFile = null;
  let simulatedPrediction = "Benign";

  const updateAnalysisProgress = (completedCount, percent, message) => {
    analysisSteps.forEach((step, index) => {
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
    if (analysisProgressLabel) analysisProgressLabel.textContent = `${String(percent).padStart(2, "0")}%`;
    if (analysisMessage) analysisMessage.textContent = message;
  };

  const acceptFile = file => {
    if (!file) return;
    const ext = file.name.toLowerCase().split(".").pop();
    if (ext !== "exe") {
      status.dataset.state = "error";
      status.textContent = "For this prototype, please upload a Portable Executable (.exe) file.";
      selectedFile = null;
      preview.classList.add("hidden");
      return;
    }
    selectedFile = file;
    // Demo-only deterministic example; replace with API/model response in implementation.
    simulatedPrediction = "Benign";
    nameEl.textContent = file.name;
    sizeEl.textContent = `${fileSize(file.size)} • ${file.type || "application/x-msdownload"}`;
    preview.classList.remove("hidden");
    status.dataset.state = "ready";
    status.textContent = "File ready for static analysis.";
  };

  pick?.addEventListener("click", ()=>input.click());
  input.addEventListener("change", e => acceptFile(e.target.files?.[0]));
  ["dragenter","dragover"].forEach(evt => drop.addEventListener(evt, e => {
    e.preventDefault(); drop.classList.add("dragover");
  }));
  ["dragleave","drop"].forEach(evt => drop.addEventListener(evt, e => {
    e.preventDefault(); drop.classList.remove("dragover");
  }));
  drop.addEventListener("drop", e => acceptFile(e.dataTransfer.files?.[0]));
  clearBtn?.addEventListener("click", ()=>{
    selectedFile = null; input.value = ""; preview.classList.add("hidden");
    delete status.dataset.state;
    status.textContent = "No file selected.";
  });
  scanBtn?.addEventListener("click", ()=>{
    if (!selectedFile) {
      status.dataset.state = "error";
      status.textContent = "Please select an .exe file first.";
      return;
    }
    scanBtn.disabled = true;
    scanBtn.innerHTML = '<span class="spinner"></span> Analyzing...';
    scanBtn.setAttribute("aria-busy", "true");
    status.dataset.state = "busy";
    status.textContent = "Validating file and extracting static features...";
    if (analysisFileName) analysisFileName.textContent = selectedFile.name;
    scanForm?.classList.add("hidden");
    analysisPanel?.classList.remove("hidden");
    updateAnalysisProgress(0, 8, "Validating the file package and PE format...");

    [
      { delay: 360, completed: 1, percent: 34, message: "Preparing static feature groups..." },
      { delay: 760, completed: 2, percent: 63, message: "Running the prototype classifier..." },
      { delay: 1180, completed: 3, percent: 87, message: "Preparing the analysis report..." }
    ].forEach(step => setTimeout(
      () => updateAnalysisProgress(step.completed, step.percent, step.message),
      step.delay
    ));

    setTimeout(()=>{
      updateAnalysisProgress(analysisSteps.length, 100, "Prototype result ready. Opening the report...");
      const result = {
        id: crypto.randomUUID ? crypto.randomUUID() : String(Date.now()),
        fileName: selectedFile.name,
        fileSize: selectedFile.size,
        fileType: "PE Executable",
        uploadedAt: new Date().toISOString(),
        algorithm: "LightGBM",
        prediction: simulatedPrediction,
        confidence: 0.973,
        falsePositiveNote: "Prototype result — connect this page to the trained model for real predictions."
      };
      const history = loadHistory();
      history.unshift(result);
      saveHistory(history.slice(0, 50));
      window.location.href = `results.html?id=${encodeURIComponent(result.id)}`;
    }, 1700);
  });
}

function setupResults() {
  const root = document.querySelector("#resultRoot");
  if (!root) return;
  const id = new URLSearchParams(location.search).get("id");
  const item = loadHistory().find(x => x.id === id) || loadHistory()[0];
  if (!item) {
    root.innerHTML = '<div class="panel scan-card empty-state"><div class="upload-icon" aria-hidden="true">?</div><h2>No scan result found</h2><p>Return to the scan page and upload an executable file to generate a result.</p><a class="btn btn-primary" href="scan.html">Start a scan</a></div>';
    return;
  }
  const isMal = item.prediction === "Malware";
  root.innerHTML = `
    <div class="result-layout">
      <aside class="panel summary-card">
        <div class="score-ring" style="border-color:${isMal ? "var(--danger)" : "var(--success)"}">
          <div>
            <div class="score">${Math.round(item.confidence*100)}%</div>
            <span>Confidence</span>
          </div>
        </div>
        <div class="result-status">
          <div class="kicker">Prediction</div>
          <h2 style="color:${isMal ? "var(--danger)" : "var(--success)"}">${esc(item.prediction)}</h2>
          <p>${isMal ? "Potentially malicious file detected." : "No malicious classification was produced by the prototype model."}</p>
        </div>
      </aside>
      <section class="result-main">
        <div class="summary-banner">
          <div>
            <div class="kicker">Detection status</div>
            <strong>${isMal ? "Potential threat detected" : "File classified as benign"}</strong>
          </div>
          <span class="badge ${isMal ? "badge-danger" : "badge-success"}">${isMal ? "MALWARE" : "BENIGN"}</span>
        </div>
        <div class="result-info">
          <div class="stat"><label>File name</label><strong>${esc(item.fileName)}</strong></div>
          <div class="stat"><label>File size</label><strong>${fileSize(item.fileSize)}</strong></div>
          <div class="stat"><label>File type</label><strong>${esc(item.fileType)}</strong></div>
          <div class="stat"><label>Algorithm</label><strong>${esc(item.algorithm)}</strong></div>
          <div class="stat"><label>Scan date</label><strong>${new Date(item.uploadedAt).toLocaleString()}</strong></div>
          <div class="stat"><label>Analysis</label><strong>Static analysis</strong></div>
        </div>
        <div class="panel scan-card">
          <div class="section-head">
            <div><h2>Static Feature Groups</h2><p>Feature categories planned for the model pipeline.</p></div>
          </div>
          <div class="feature-grid">
            <div class="small-card"><h4>PE Headers</h4><p>Executable structure and header-related characteristics.</p></div>
            <div class="small-card"><h4>Imported / Exported Functions</h4><p>Function usage that can help distinguish suspicious files.</p></div>
            <div class="small-card"><h4>Strings & Entropy</h4><p>Textual indicators and randomness-related characteristics.</p></div>
            <div class="small-card"><h4>Byte / Opcode Features</h4><p>Low-level executable patterns used for classification.</p></div>
          </div>
          <div class="notice" style="margin-top:16px">${esc(item.falsePositiveNote)}</div>
        </div>
      </section>
    </div>`;
}

function setupHistory() {
  const body = document.querySelector("#historyBody");
  if (!body) return;
  const history = loadHistory();
  if (!history.length) {
    body.innerHTML = `<div class="panel scan-card empty-state"><div class="upload-icon" aria-hidden="true">↗</div><h3>No scans yet</h3><p>Your prototype scan history will appear here after a file is analyzed.</p><a class="btn btn-primary" href="scan.html">Scan a file</a></div>`;
    return;
  }
  body.innerHTML = `<div class="history-list">${history.map(item => `
    <a class="history-row" href="results.html?id=${encodeURIComponent(item.id)}">
      <div><strong>${esc(item.fileName)}</strong><div class="muted">${esc(item.fileType)}</div></div>
      <div><span class="badge ${item.prediction === "Malware" ? "badge-danger" : "badge-success"}">${esc(item.prediction)}</span></div>
      <div class="hide-md muted">${fileSize(item.fileSize)}</div>
      <div class="hide-md muted">${new Date(item.uploadedAt).toLocaleString()}</div>
      <div class="badge badge-neutral">${esc(item.algorithm)}</div>
    </a>`).join("")}</div>`;
}

document.addEventListener("DOMContentLoaded", ()=>{
  setupScanner();
  setupResults();
  setupHistory();
});
