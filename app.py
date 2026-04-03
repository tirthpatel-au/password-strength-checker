from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


ROOT = Path(__file__).parent
COMMON_PATTERNS = {
    "password",
    "admin",
    "welcome",
    "qwerty",
    "letmein",
    "summer",
    "winter",
    "spring",
    "autumn",
    "football",
    "dragon",
    "monkey",
    "abc123",
    "secret",
    "login",
    "passw0rd",
}
SEQUENCES = (
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiopasdfghjklzxcvbnm",
)
YEAR_PATTERN = re.compile(r"(19\d{2}|20\d{2})")
SPACE_PATTERN = re.compile(r"\s")
LOWER_PATTERN = re.compile(r"[a-z]")
UPPER_PATTERN = re.compile(r"[A-Z]")
DIGIT_PATTERN = re.compile(r"\d")
SYMBOL_PATTERN = re.compile(r"[^A-Za-z0-9\s]")
REPEAT_PATTERN = re.compile(r"(.)\1{2,}")


@dataclass
class AttackScenario:
    label: str
    guesses_per_second: float


ATTACK_SCENARIOS = (
    AttackScenario("Rate-limited online attack", 10),
    AttackScenario("Credential stuffing attack", 10_000),
    AttackScenario("Offline hash cracking", 10_000_000_000),
)


def estimate_charset(password: str) -> int:
    charset = 0
    if LOWER_PATTERN.search(password):
        charset += 26
    if UPPER_PATTERN.search(password):
        charset += 26
    if DIGIT_PATTERN.search(password):
        charset += 10
    if SYMBOL_PATTERN.search(password):
        charset += 33
    if SPACE_PATTERN.search(password):
        charset += 1
    return max(charset, 1)


def find_sequences(password: str) -> list[str]:
    lowered = password.lower()
    hits: list[str] = []
    for sequence in SEQUENCES:
        for index in range(len(sequence) - 2):
            chunk = sequence[index : index + 3]
            reverse_chunk = chunk[::-1]
            if chunk in lowered or reverse_chunk in lowered:
                hits.append(chunk)
    return sorted(set(hits))


def format_duration(seconds: float) -> str:
    if seconds <= 0 or not math.isfinite(seconds):
        return "Instant"

    units = (
        ("centuries", 60 * 60 * 24 * 365 * 100),
        ("years", 60 * 60 * 24 * 365),
        ("days", 60 * 60 * 24),
        ("hours", 60 * 60),
        ("minutes", 60),
        ("seconds", 1),
    )
    for label, size in units:
        if seconds >= size:
            value = round(seconds / size, 1)
            return f"{value} {label}"
    return "Less than a second"


def meter_state(score: int) -> str:
    if score >= 85:
        return "excellent"
    if score >= 70:
        return "strong"
    if score >= 50:
        return "moderate"
    if score >= 30:
        return "weak"
    return "critical"


def analyze_password(password: str) -> dict[str, Any]:
    if not password:
        return {
            "score": 0,
            "state": "critical",
            "headline": "Ready for inspection",
            "rating": "No password entered",
            "entropy_bits": 0,
            "findings": ["Enter a password to see a live security profile."],
            "advice": [
                "Aim for 16 or more characters.",
                "Use a unique passphrase for every account.",
                "Turn on MFA for sensitive accounts.",
            ],
            "metrics": {
                "length": 0,
                "unique_chars": 0,
                "pattern_load": "None",
                "memory_style": "Unknown",
            },
            "behavior_flags": [
                {
                    "title": "User behavior matters",
                    "detail": "Even a strong-looking password becomes risky if it is reused across sites.",
                }
            ],
            "attack_windows": [
                {"label": scenario.label, "time": "Instant"}
                for scenario in ATTACK_SCENARIOS
            ],
        }

    score = 18
    findings: list[str] = []
    advice: list[str] = []
    behavior_flags: list[dict[str, str]] = []

    length = len(password)
    unique_chars = len(set(password))
    charset = estimate_charset(password)
    raw_entropy = length * math.log2(charset)
    sequence_hits = find_sequences(password)
    lowered = password.lower()
    common_hits = sorted(pattern for pattern in COMMON_PATTERNS if pattern in lowered)

    score += min(length * 2.8, 34)
    score += min(unique_chars * 1.3, 18)

    if LOWER_PATTERN.search(password):
        score += 5
    else:
        advice.append("Add lowercase characters to increase variety.")

    if UPPER_PATTERN.search(password):
        score += 5
    else:
        advice.append("Add uppercase characters without relying on only the first letter.")

    if DIGIT_PATTERN.search(password):
        score += 5
    else:
        advice.append("Add numbers that are not obvious dates or endings.")

    if SYMBOL_PATTERN.search(password):
        score += 7
    else:
        advice.append("Symbols help, but length and unpredictability matter more than decoration.")

    if SPACE_PATTERN.search(password):
        score += 4
        behavior_flags.append(
            {
                "title": "Passphrase-friendly",
                "detail": "Whitespace suggests a phrase-based structure, which can help when the words are uncommon.",
            }
        )

    if length < 10:
        score -= 26
        findings.append("The password is short enough that brute-force resistance drops sharply.")
    elif length < 14:
        score -= 10
        findings.append("Length is acceptable, but it is still below a robust modern passphrase target.")
    elif length < 18:
        score += 8
        findings.append("Length is doing real defensive work here.")
    else:
        score += 14
        findings.append("Excellent length provides a strong base against brute-force attacks.")

    if common_hits:
        penalty = min(24, 10 + len(common_hits) * 6)
        score -= penalty
        findings.append(f"Contains common attacker-first patterns: {', '.join(common_hits[:3])}.")
        behavior_flags.append(
            {
                "title": "Predictable vocabulary",
                "detail": "Attackers prioritize common words, seasons, and keyboard habits before searching the full space.",
            }
        )

    if YEAR_PATTERN.search(password):
        score -= 12
        findings.append("Date-like fragments make the password easier to guess from personal context.")
        behavior_flags.append(
            {
                "title": "Personal data risk",
                "detail": "Years often come from birthdays, anniversaries, or current dates that attackers test early.",
            }
        )

    if REPEAT_PATTERN.search(password):
        score -= 10
        findings.append("Repeated characters reduce effective randomness.")

    if sequence_hits:
        score -= min(18, len(sequence_hits) * 4)
        findings.append("Sequential patterns such as keyboard walks or number runs were detected.")

    if unique_chars <= max(4, length // 2):
        score -= 12
        findings.append("Low character diversity suggests predictable internal repetition.")

    if lowered == password or password == password.upper():
        behavior_flags.append(
            {
                "title": "Single-case habit",
                "detail": "Passwords built in one casing style are easier to generate and easier for attackers to model.",
            }
        )

    if "-" in password or " " in password:
        behavior_flags.append(
            {
                "title": "Memorable separator",
                "detail": "Separators can help memory, but the surrounding words still need to be unusual and unique.",
            }
        )

    if not findings:
        findings.append("No obvious weak patterns were detected in the sampled heuristics.")

    if score < 50:
        advice.insert(
            0,
            "Switch to a longer passphrase with 4 or 5 unrelated words plus distinctive separators.",
        )

    if not common_hits and length >= 16 and unique_chars >= 10:
        advice.append("This is structurally solid. Keep it unique and store it in a password manager.")

    advice.append("Never reuse this password on another account.")
    advice.append("Pair strong passwords with MFA for high-value accounts.")

    score = max(0, min(100, round(score)))
    entropy_bits = max(0, round(raw_entropy - max(0, 60 - score) * 0.45))

    combinations = max(1.0, 2 ** min(entropy_bits, 62))
    attack_windows = [
        {
            "label": scenario.label,
            "time": format_duration(combinations / scenario.guesses_per_second),
        }
        for scenario in ATTACK_SCENARIOS
    ]

    if score >= 85:
        headline = "Resilient under pressure"
        rating = "Excellent"
    elif score >= 70:
        headline = "Strong with minor exposure"
        rating = "Strong"
    elif score >= 50:
        headline = "Usable but improvable"
        rating = "Moderate"
    elif score >= 30:
        headline = "Predictable under attack"
        rating = "Weak"
    else:
        headline = "High-risk credential"
        rating = "Critical"

    pattern_load = "High" if common_hits or sequence_hits else "Low"
    if pattern_load == "Low" and YEAR_PATTERN.search(password):
        pattern_load = "Medium"

    memory_style = "Passphrase" if (" " in password or "-" in password) and length >= 14 else "Composed password"

    return {
        "score": score,
        "state": meter_state(score),
        "headline": headline,
        "rating": rating,
        "entropy_bits": entropy_bits,
        "findings": findings[:4],
        "advice": list(dict.fromkeys(advice))[:5],
        "metrics": {
            "length": length,
            "unique_chars": unique_chars,
            "pattern_load": pattern_load,
            "memory_style": memory_style,
        },
        "behavior_flags": behavior_flags[:4]
        or [
            {
                "title": "No immediate habit warning",
                "detail": "The checker did not spot a dominant user-behavior pattern, but uniqueness still matters.",
            }
        ],
        "attack_windows": attack_windows,
    }


class PasswordHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path in ("/", "/index.html"):
            self._serve_file("index.html", "text/html; charset=utf-8")
            return
        if self.path == "/styles.css":
            self._serve_file("styles.css", "text/css; charset=utf-8")
            return
        if self.path == "/script.js":
            self._serve_file("script.js", "application/javascript; charset=utf-8")
            return
        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def do_POST(self) -> None:
        if self.path != "/api/analyze":
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(content_length)

        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except json.JSONDecodeError:
            self._send_json({"error": "Invalid JSON"}, status=HTTPStatus.BAD_REQUEST)
            return

        password = str(payload.get("password", ""))
        self._send_json(analyze_password(password))

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _serve_file(self, filename: str, content_type: str) -> None:
        file_path = ROOT / filename
        if not file_path.exists():
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")
            return

        content = file_path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _send_json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        content = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


def run() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 8000), PasswordHandler)
    print("Password strength checker running at http://127.0.0.1:8000")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    run()
