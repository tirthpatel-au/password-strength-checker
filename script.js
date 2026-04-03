const passwordInput = document.getElementById("passwordInput");
const toggleVisibilityButton = document.getElementById("toggleVisibility");
const meterFill = document.getElementById("meterFill");
const meterLabel = document.getElementById("meterLabel");
const meterScore = document.getElementById("meterScore");
const ringScore = document.getElementById("ringScore");
const scoreRing = document.getElementById("scoreRing");
const headline = document.getElementById("headline");
const rating = document.getElementById("rating");
const entropyBits = document.getElementById("entropyBits");
const patternLoad = document.getElementById("patternLoad");
const metricLength = document.getElementById("metricLength");
const metricUnique = document.getElementById("metricUnique");
const memoryStyle = document.getElementById("memoryStyle");
const findingsList = document.getElementById("findingsList");
const adviceList = document.getElementById("adviceList");
const behaviorList = document.getElementById("behaviorList");
const attackTimeline = document.getElementById("attackTimeline");

let debounceTimer;

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function renderList(element, items) {
  element.innerHTML = items.map((item) => `<li>${escapeHtml(item)}</li>`).join("");
}

function renderBehavior(items) {
  behaviorList.innerHTML = items
    .map(
      (item) => `
        <article class="behavior-card">
          <strong>${escapeHtml(item.title)}</strong>
          <div class="behavior-copy">${escapeHtml(item.detail)}</div>
        </article>
      `,
    )
    .join("");
}

function renderTimeline(items) {
  attackTimeline.innerHTML = items
    .map(
      (item) => `
        <article class="timeline-card">
          <strong>${escapeHtml(item.label)}</strong>
          <p>${escapeHtml(item.time)}</p>
        </article>
      `,
    )
    .join("");
}

function setStateClasses(state) {
  const states = ["critical", "weak", "moderate", "strong", "excellent"];
  meterFill.classList.remove(...states);
  scoreRing.classList.remove(...states);
  meterFill.classList.add(state);
  scoreRing.classList.add(state);
}

function applyResult(result) {
  meterFill.style.width = `${result.score}%`;
  meterLabel.textContent = result.headline;
  meterScore.textContent = `${result.score} / 100`;
  ringScore.textContent = result.score;
  headline.textContent = result.headline;
  rating.textContent = result.rating;
  entropyBits.textContent = `${result.entropy_bits} bits`;
  patternLoad.textContent = result.metrics.pattern_load;
  metricLength.textContent = result.metrics.length;
  metricUnique.textContent = result.metrics.unique_chars;
  memoryStyle.textContent = result.metrics.memory_style;
  setStateClasses(result.state);
  renderList(findingsList, result.findings);
  renderList(adviceList, result.advice);
  renderBehavior(result.behavior_flags);
  renderTimeline(result.attack_windows);
}

async function analyzePassword() {
  const response = await fetch("/api/analyze", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ password: passwordInput.value }),
  });

  if (!response.ok) {
    throw new Error("Analysis failed");
  }

  const result = await response.json();
  applyResult(result);
}

function queueAnalysis() {
  window.clearTimeout(debounceTimer);
  debounceTimer = window.setTimeout(() => {
    analyzePassword().catch(() => {
      meterLabel.textContent = "Python service unavailable";
      rating.textContent = "Check the local server";
    });
  }, 130);
}

passwordInput.addEventListener("input", queueAnalysis);

toggleVisibilityButton.addEventListener("click", () => {
  const nextType = passwordInput.type === "password" ? "text" : "password";
  passwordInput.type = nextType;
  toggleVisibilityButton.textContent = nextType === "password" ? "Reveal" : "Hide";
});

analyzePassword().catch(() => {
  meterLabel.textContent = "Start the Python server";
  rating.textContent = "Run python app.py";
});
