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
const primaryCrackTime = document.getElementById("primaryCrackTime");
const primaryCrackLabel = document.getElementById("primaryCrackLabel");
const metricLength = document.getElementById("metricLength");
const metricUnique = document.getElementById("metricUnique");
const memoryStyle = document.getElementById("memoryStyle");
const findingsList = document.getElementById("findingsList");
const adviceList = document.getElementById("adviceList");
const behaviorList = document.getElementById("behaviorList");
const attackTimeline = document.getElementById("attackTimeline");
const scrollProgressBar = document.getElementById("scrollProgressBar");
const wordCountInput = document.getElementById("wordCount");
const separatorType = document.getElementById("separatorType");
const generatedPassword = document.getElementById("generatedPassword");
const generatePasswordButton = document.getElementById("generatePassword");
const copyGeneratedPasswordButton = document.getElementById("copyGeneratedPassword");

const WORD_BANK = [
  "anchor",
  "bamboo",
  "canyon",
  "drift",
  "ember",
  "falcon",
  "harbor",
  "ivy",
  "jungle",
  "kelp",
  "lantern",
  "meadow",
  "nebula",
  "onyx",
  "pepper",
  "quartz",
  "river",
  "saffron",
  "thunder",
  "umbra",
  "velvet",
  "willow",
  "xenon",
  "yonder",
  "zephyr",
  "atlas",
  "breeze",
  "copper",
  "dawn",
  "echo",
  "frost",
  "grove",
  "hazel",
  "iris",
  "juniper",
  "kiwi",
  "lotus",
  "mango",
  "nova",
  "opal",
  "prairie",
  "raven",
  "signal",
  "timber",
  "violet",
  "walnut",
];
const MIX_SEPARATORS = ["-", "_", "*", ",", " ", "number"];

let debounceTimer;

function updateScrollEffects() {
  const scrollTop = window.scrollY;
  const scrollable = document.documentElement.scrollHeight - window.innerHeight;
  const progress = scrollable > 0 ? (scrollTop / scrollable) * 100 : 0;
  document.documentElement.style.setProperty("--scroll-y", String(scrollTop));

  if (scrollProgressBar) {
    scrollProgressBar.style.width = `${Math.min(progress, 100)}%`;
  }
}

function setupRevealAnimations() {
  const revealItems = document.querySelectorAll(".reveal");
  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          observer.unobserve(entry.target);
        }
      }
    },
    {
      threshold: 0.16,
      rootMargin: "0px 0px -40px 0px",
    },
  );

  revealItems.forEach((item, index) => {
    item.style.setProperty("--reveal-delay", `${Math.min(index * 55, 360)}ms`);
    observer.observe(item);
  });
}

function animateButtonPress(button) {
  button.classList.remove("is-pressed");
  window.requestAnimationFrame(() => {
    button.classList.add("is-pressed");
  });
}

function randomInt(max) {
  if (!window.crypto) {
    return Math.floor(Math.random() * max);
  }

  const values = new Uint32Array(1);
  window.crypto.getRandomValues(values);
  return values[0] % max;
}

function pickRandom(items) {
  return items[randomInt(items.length)];
}

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

function updatePrimaryCrackTime(items) {
  const offlineEstimate = items.find((item) => item.label === "Offline hash cracking");
  const estimate = offlineEstimate || items.at(-1);

  if (!estimate) {
    primaryCrackTime.textContent = "Instant";
    primaryCrackLabel.textContent = "Offline hash cracking";
    return;
  }

  primaryCrackTime.textContent = estimate.time;
  primaryCrackLabel.textContent = estimate.label;
}

function getSeparator() {
  const selected = separatorType.value;

  if (selected === "number") {
    return String(randomInt(10));
  }

  if (selected === "mix") {
    const mixedSeparator = pickRandom(MIX_SEPARATORS);
    return mixedSeparator === "number" ? String(randomInt(10)) : mixedSeparator;
  }

  return selected;
}

function generatePassphrase() {
  const requestedCount = Number.parseInt(wordCountInput.value, 10);
  const wordCount = Math.min(Math.max(requestedCount || 4, 3), 10);
  wordCountInput.value = String(wordCount);
  const words = [];

  while (words.length < wordCount) {
    const word = pickRandom(WORD_BANK);
    if (!words.includes(word)) {
      words.push(word);
    }
  }

  const password = words
    .map((word, index) => (index % 2 === 0 ? word : `${word[0].toUpperCase()}${word.slice(1)}`))
    .reduce((parts, word, index) => {
      if (index > 0) {
        parts.push(getSeparator());
      }
      parts.push(word);
      return parts;
    }, [])
    .join("");

  generatedPassword.textContent = password;
  copyGeneratedPasswordButton.textContent = "Copy password";
  passwordInput.value = password;
  analyzePassword().catch(() => {
    meterLabel.textContent = "Python service unavailable";
    rating.textContent = "Check the local server";
  });
}

async function copyGeneratedPassword() {
  const password = generatedPassword.textContent.trim();
  if (!password || password.startsWith("Choose options")) {
    copyGeneratedPasswordButton.textContent = "Generate first";
    return;
  }

  try {
    if (navigator.clipboard) {
      await navigator.clipboard.writeText(password);
    } else {
      const textArea = document.createElement("textarea");
      textArea.value = password;
      textArea.setAttribute("readonly", "");
      textArea.style.position = "fixed";
      textArea.style.opacity = "0";
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand("copy");
      document.body.removeChild(textArea);
    }
    copyGeneratedPasswordButton.textContent = "Copied";
  } catch {
    copyGeneratedPasswordButton.textContent = "Copy unavailable";
  }
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
  updatePrimaryCrackTime(result.attack_windows);
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
  animateButtonPress(toggleVisibilityButton);
});

toggleVisibilityButton.addEventListener("animationend", () => {
  toggleVisibilityButton.classList.remove("is-pressed");
});

generatePasswordButton.addEventListener("click", () => {
  generatePassphrase();
  animateButtonPress(generatePasswordButton);
});

copyGeneratedPasswordButton.addEventListener("click", () => {
  copyGeneratedPassword();
  animateButtonPress(copyGeneratedPasswordButton);
});

generatePasswordButton.addEventListener("animationend", () => {
  generatePasswordButton.classList.remove("is-pressed");
});

copyGeneratedPasswordButton.addEventListener("animationend", () => {
  copyGeneratedPasswordButton.classList.remove("is-pressed");
});

window.addEventListener("scroll", updateScrollEffects, { passive: true });

setupRevealAnimations();
updateScrollEffects();

analyzePassword().catch(() => {
  meterLabel.textContent = "Start the Python server";
  rating.textContent = "Run python app.py";
});
