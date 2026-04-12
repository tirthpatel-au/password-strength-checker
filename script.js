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
const breachCallout = document.getElementById("breachCallout");
const breachHeadline = document.getElementById("breachHeadline");
const breachDetail = document.getElementById("breachDetail");
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
  "anchor", "atlas", "bamboo", "breeze", "canyon", "copper", "dawn", "drift",
  "echo", "ember", "falcon", "frost", "grove", "harbor", "hazel", "iris",
  "ivy", "jungle", "juniper", "kelp", "kiwi", "lantern", "lotus", "mango",
  "meadow", "nebula", "nova", "onyx", "opal", "pepper", "prairie", "quartz",
  "raven", "river", "saffron", "signal", "thunder", "timber", "umbra",
  "velvet", "violet", "walnut", "willow", "xenon", "yonder", "zephyr",
];
const MIX_SEPARATORS = ["-", "_", "*", ",", " ", "number"];
const COMMON_PATTERNS = [
  "password", "admin", "welcome", "qwerty", "letmein", "summer", "winter",
  "spring", "autumn", "football", "dragon", "monkey", "abc123", "secret",
  "login", "passw0rd",
];
const SEQUENCES = [
  "abcdefghijklmnopqrstuvwxyz",
  "0123456789",
  "qwertyuiopasdfghjklzxcvbnm",
];
const ATTACK_SCENARIOS = [
  { label: "Rate-limited online attack", guessesPerSecond: 10 },
  { label: "Credential stuffing attack", guessesPerSecond: 10_000 },
  { label: "Offline hash cracking", guessesPerSecond: 10_000_000_000 },
];
const BREACH_CACHE = new Map();
const USE_LOCAL_ANALYZER = !["127.0.0.1", "localhost"].includes(window.location.hostname);

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

function updateBreachStatus(result) {
  const breach = result.breach_check;
  breachCallout.classList.remove("is-breached", "is-clear", "is-unavailable");
  breachHeadline.textContent = breach.headline;
  breachDetail.textContent = breach.detail;

  if (breach.status === "breached") {
    breachCallout.classList.add("is-breached");
  } else if (breach.status === "clear") {
    breachCallout.classList.add("is-clear");
  } else if (breach.status === "unavailable") {
    breachCallout.classList.add("is-unavailable");
  }
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
    meterLabel.textContent = "Analysis unavailable";
    rating.textContent = "Try again in a moment";
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
  updateBreachStatus(result);
  renderTimeline(result.attack_windows);
}

function estimateCharset(password) {
  let charset = 0;
  if (/[a-z]/.test(password)) charset += 26;
  if (/[A-Z]/.test(password)) charset += 26;
  if (/\d/.test(password)) charset += 10;
  if (/[^A-Za-z0-9\s]/.test(password)) charset += 33;
  if (/\s/.test(password)) charset += 1;
  return Math.max(charset, 1);
}

function findSequences(password) {
  const lowered = password.toLowerCase();
  const hits = new Set();

  for (const sequence of SEQUENCES) {
    for (let index = 0; index < sequence.length - 2; index += 1) {
      const chunk = sequence.slice(index, index + 3);
      const reverseChunk = [...chunk].reverse().join("");
      if (lowered.includes(chunk) || lowered.includes(reverseChunk)) {
        hits.add(chunk);
      }
    }
  }

  return [...hits].sort();
}

function formatDuration(seconds) {
  if (seconds <= 0 || !Number.isFinite(seconds)) {
    return "Instant";
  }

  if (seconds < 1) {
    return "Less than a second";
  }

  const secondsPerMinute = 60;
  const secondsPerHour = secondsPerMinute * 60;
  const secondsPerDay = secondsPerHour * 24;
  const secondsPerYear = secondsPerDay * 365;

  if (seconds >= secondsPerYear) {
    return formatYears(seconds / secondsPerYear);
  }

  const units = [
    ["day", "days", secondsPerDay],
    ["hour", "hours", secondsPerHour],
    ["minute", "minutes", secondsPerMinute],
    ["second", "seconds", 1],
  ];

  for (const [singularLabel, pluralLabel, size] of units) {
    if (seconds >= size) {
      const value = seconds / size;
      const displayValue = value < 10 ? Math.round(value * 10) / 10 : Math.round(value);
      const label = displayValue === 1 ? singularLabel : pluralLabel;
      return `${displayValue} ${label}`;
    }
  }

  return "Less than a second";
}

function formatYears(years) {
  const largeUnits = [
    [1_000_000_000_000, "trillion years"],
    [1_000_000_000, "billion years"],
    [1_000_000, "million years"],
  ];

  for (const [size, label] of largeUnits) {
    if (years >= size) {
      const value = years / size;
      const displayValue = value < 10 ? Math.round(value * 10) / 10 : Math.round(value);
      return `Over ${displayValue} ${label}`;
    }
  }

  if (years >= 100) {
    const centuries = years / 100;
    const displayValue = centuries < 10 ? Math.round(centuries * 10) / 10 : Math.round(centuries);
    const label = displayValue === 1 ? "century" : "centuries";
    return `${displayValue} ${label}`;
  }

  const displayValue = years < 10 ? Math.round(years * 10) / 10 : Math.round(years);
  const label = displayValue === 1 ? "year" : "years";
  return `${displayValue} ${label}`;
}

function formatCrackDuration(entropyBitsValue, guessesPerSecond) {
  if (entropyBitsValue <= 0) {
    return "Instant";
  }

  const log10Seconds = entropyBitsValue * Math.log10(2) - Math.log10(guessesPerSecond);
  if (log10Seconds < 6) {
    return formatDuration((2 ** entropyBitsValue) / guessesPerSecond);
  }

  const secondsPerYear = 60 * 60 * 24 * 365;
  const log10Years = log10Seconds - Math.log10(secondsPerYear);
  if (log10Years >= 0) {
    return formatYears(10 ** Math.min(log10Years, 308));
  }

  return formatDuration(10 ** log10Seconds);
}

async function sha1Hex(value) {
  if (!window.crypto?.subtle) {
    throw new Error("SHA-1 unavailable");
  }

  const encoded = new TextEncoder().encode(value);
  const hashBuffer = await window.crypto.subtle.digest("SHA-1", encoded);
  const hashArray = [...new Uint8Array(hashBuffer)];
  return hashArray.map((byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
}

async function lookupBreachCountLocal(password) {
  const sha1Hash = await sha1Hex(password);
  if (BREACH_CACHE.has(sha1Hash)) {
    return BREACH_CACHE.get(sha1Hash);
  }

  const prefix = sha1Hash.slice(0, 5);
  const suffix = sha1Hash.slice(5);
  const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
  if (!response.ok) {
    throw new Error("Breach lookup failed");
  }

  const payload = await response.text();
  let count = 0;
  for (const line of payload.split(/\r?\n/)) {
    const [hashSuffix, hashCount] = line.split(":");
    if (hashSuffix === suffix) {
      count = Number.parseInt(hashCount || "0", 10) || 0;
      break;
    }
  }

  BREACH_CACHE.set(sha1Hash, count);
  return count;
}

async function breachCheckPayloadLocal(password) {
  if (!password) {
    return {
      status: "idle",
      count: 0,
      headline: "Not checked yet",
      detail: "Enter a password to check if it has appeared in known breaches.",
    };
  }

  try {
    const breachCount = await lookupBreachCountLocal(password);
    if (breachCount > 0) {
      return {
        status: "breached",
        count: breachCount,
        headline: "Previously breached password",
        detail: `This password has appeared in breach data ${breachCount.toLocaleString()} times. Do not use it.`,
      };
    }

    return {
      status: "clear",
      count: 0,
      headline: "No breach found",
      detail: "This password was not found in the breach data checked by the service.",
    };
  } catch {
    return {
      status: "unavailable",
      count: 0,
      headline: "Breach check unavailable",
      detail: "The breach database could not be reached right now. Try again in a moment.",
    };
  }
}

async function analyzePasswordLocal(password) {
  if (!password) {
    return {
      score: 0,
      state: "critical",
      headline: "Ready for inspection",
      rating: "No password entered",
      entropy_bits: 0,
      findings: ["Enter a password to see a live security profile."],
      advice: [
        "Aim for 16 or more characters.",
        "Use a unique passphrase for every account.",
        "Turn on MFA for sensitive accounts.",
      ],
      metrics: {
        length: 0,
        unique_chars: 0,
        pattern_load: "None",
        memory_style: "Unknown",
      },
      behavior_flags: [
        {
          title: "User behavior matters",
          detail: "Even a strong-looking password becomes risky if it is reused across sites.",
        },
      ],
      breach_check: await breachCheckPayloadLocal(password),
      attack_windows: ATTACK_SCENARIOS.map((scenario) => ({
        label: scenario.label,
        time: "Instant",
      })),
    };
  }

  let score = 18;
  const findings = [];
  const advice = [];
  const behaviorFlags = [];
  const breachCheck = await breachCheckPayloadLocal(password);

  const length = password.length;
  const uniqueChars = new Set(password).size;
  const charset = estimateCharset(password);
  const rawEntropy = length * Math.log2(charset);
  const sequenceHits = findSequences(password);
  const lowered = password.toLowerCase();
  const commonHits = COMMON_PATTERNS.filter((pattern) => lowered.includes(pattern)).sort();

  score += Math.min(length * 2.8, 34);
  score += Math.min(uniqueChars * 1.3, 18);

  if (/[a-z]/.test(password)) {
    score += 5;
  } else {
    advice.push("Add lowercase characters to increase variety.");
  }

  if (/[A-Z]/.test(password)) {
    score += 5;
  } else {
    advice.push("Add uppercase characters without relying on only the first letter.");
  }

  if (/\d/.test(password)) {
    score += 5;
  } else {
    advice.push("Add numbers that are not obvious dates or endings.");
  }

  if (/[^A-Za-z0-9\s]/.test(password)) {
    score += 7;
  } else {
    advice.push("Symbols help, but length and unpredictability matter more than decoration.");
  }

  if (/\s/.test(password)) {
    score += 4;
    behaviorFlags.push({
      title: "Passphrase-friendly",
      detail: "Whitespace suggests a phrase-based structure, which can help when the words are uncommon.",
    });
  }

  if (length < 10) {
    score -= 26;
    findings.push("The password is short enough that brute-force resistance drops sharply.");
  } else if (length < 14) {
    score -= 10;
    findings.push("Length is acceptable, but it is still below a robust modern passphrase target.");
  } else if (length < 18) {
    score += 8;
    findings.push("Length is doing real defensive work here.");
  } else {
    score += 14;
    findings.push("Excellent length provides a strong base against brute-force attacks.");
  }

  if (commonHits.length > 0) {
    const penalty = Math.min(24, 10 + commonHits.length * 6);
    score -= penalty;
    findings.push(`Contains common attacker-first patterns: ${commonHits.slice(0, 3).join(", ")}.`);
    behaviorFlags.push({
      title: "Predictable vocabulary",
      detail: "Attackers prioritize common words, seasons, and keyboard habits before searching the full space.",
    });
  }

  if (/(19\d{2}|20\d{2})/.test(password)) {
    score -= 12;
    findings.push("Date-like fragments make the password easier to guess from personal context.");
    behaviorFlags.push({
      title: "Personal data risk",
      detail: "Years often come from birthdays, anniversaries, or current dates that attackers test early.",
    });
  }

  if (/(.)\1{2,}/.test(password)) {
    score -= 10;
    findings.push("Repeated characters reduce effective randomness.");
  }

  if (sequenceHits.length > 0) {
    score -= Math.min(18, sequenceHits.length * 4);
    findings.push("Sequential patterns such as keyboard walks or number runs were detected.");
  }

  if (uniqueChars <= Math.max(4, Math.floor(length / 2))) {
    score -= 12;
    findings.push("Low character diversity suggests predictable internal repetition.");
  }

  if (lowered === password || password === password.toUpperCase()) {
    behaviorFlags.push({
      title: "Single-case habit",
      detail: "Passwords built in one casing style are easier to generate and easier for attackers to model.",
    });
  }

  if (password.includes("-") || password.includes(" ")) {
    behaviorFlags.push({
      title: "Memorable separator",
      detail: "Separators can help memory, but the surrounding words still need to be unusual and unique.",
    });
  }

  if (findings.length === 0) {
    findings.push("No obvious weak patterns were detected in the sampled heuristics.");
  }

  if (score < 50) {
    advice.unshift("Switch to a longer passphrase with 4 or 5 unrelated words plus distinctive separators.");
  }

  if (commonHits.length === 0 && length >= 16 && uniqueChars >= 10) {
    advice.push("This is structurally solid. Keep it unique and store it in a password manager.");
  }

  advice.push("Never reuse this password on another account.");
  advice.push("Pair strong passwords with MFA for high-value accounts.");

  if (breachCheck.status === "breached") {
    score = Math.min(score, 18);
    findings.unshift("This password has appeared in known breach data before.");
    advice.unshift("Replace breached passwords immediately and never reuse them on any account.");
  } else if (breachCheck.status === "unavailable") {
    findings.unshift("Breach status could not be verified right now.");
  }

  score = Math.max(0, Math.min(100, Math.round(score)));
  const entropyBitsValue = Math.max(0, Math.round(rawEntropy - Math.max(0, 60 - score) * 0.45));
  const attackWindows = ATTACK_SCENARIOS.map((scenario) => ({
    label: scenario.label,
    time: formatCrackDuration(entropyBitsValue, scenario.guessesPerSecond),
  }));

  let resultHeadline = "High-risk credential";
  let resultRating = "Critical";
  if (score >= 85) {
    resultHeadline = "Resilient under pressure";
    resultRating = "Excellent";
  } else if (score >= 70) {
    resultHeadline = "Strong with minor exposure";
    resultRating = "Strong";
  } else if (score >= 50) {
    resultHeadline = "Usable but improvable";
    resultRating = "Moderate";
  } else if (score >= 30) {
    resultHeadline = "Predictable under attack";
    resultRating = "Weak";
  }

  let patternLoadValue = commonHits.length > 0 || sequenceHits.length > 0 ? "High" : "Low";
  if (patternLoadValue === "Low" && /(19\d{2}|20\d{2})/.test(password)) {
    patternLoadValue = "Medium";
  }

  const memoryStyleValue =
    (password.includes(" ") || password.includes("-")) && length >= 14
      ? "Passphrase"
      : "Composed password";

  return {
    score,
    state: score >= 85 ? "excellent" : score >= 70 ? "strong" : score >= 50 ? "moderate" : score >= 30 ? "weak" : "critical",
    headline: resultHeadline,
    rating: resultRating,
    entropy_bits: entropyBitsValue,
    findings: findings.slice(0, 4),
    advice: [...new Set(advice)].slice(0, 5),
    metrics: {
      length,
      unique_chars: uniqueChars,
      pattern_load: patternLoadValue,
      memory_style: memoryStyleValue,
    },
    behavior_flags:
      behaviorFlags.slice(0, 4).length > 0
        ? behaviorFlags.slice(0, 4)
        : [
            {
              title: "No immediate habit warning",
              detail: "The checker did not spot a dominant user-behavior pattern, but uniqueness still matters.",
            },
          ],
    breach_check: breachCheck,
    attack_windows: attackWindows,
  };
}

async function analyzePassword() {
  if (!USE_LOCAL_ANALYZER) {
    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ password: passwordInput.value }),
      });

      if (response.ok) {
        const result = await response.json();
        applyResult(result);
        return;
      }
    } catch {
      // Fall through to local analyzer so GitHub Pages and local fallback both work.
    }
  }

  const result = await analyzePasswordLocal(passwordInput.value);
  applyResult(result);
}

function queueAnalysis() {
  window.clearTimeout(debounceTimer);
  debounceTimer = window.setTimeout(() => {
    analyzePassword().catch(() => {
      meterLabel.textContent = "Analysis unavailable";
      rating.textContent = "Try again in a moment";
    });
  }, 350);
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
  meterLabel.textContent = "Analysis unavailable";
  rating.textContent = "Try again in a moment";
});
