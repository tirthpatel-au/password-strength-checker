# Password Strength Checker

A Python-powered password strength checker with a high-impact UI focused on authentication security, brute-force risk, and real-time user guidance.

## Demo

[Open the live demo](https://tirthpatel-au.github.io/password-strength-checker/)

For local development, run `python app.py` and open `http://127.0.0.1:8000`.

## Overview

This project analyzes password quality instantly and explains why a password is weak, moderate, or strong. It goes beyond a simple score by surfacing:

- brute-force resistance
- entropy estimates
- predictable password patterns
- user behavior risks such as reusable structures and personal-date habits
- actionable advice for stronger credential creation

## Features

- Live password analysis through a local Python server
- Animated strength meter and score ring
- Entropy estimate and attack-window projections
- Detection of common words, repeated characters, years, and keyboard sequences
- Behavioral risk cards explaining real-world password weaknesses
- Strong-vs-weak examples for better security education
- Mobile-friendly, polished interface

## Project Structure

- `app.py` - Python HTTP server and password analysis engine
- `index.html` - Main UI markup
- `styles.css` - Visual design and responsive layout
- `script.js` - Frontend behavior and API integration

## Requirements

- Python 3.10 or newer recommended

## Clone The Repository

```bash
git clone https://github.com/tirthpatel-au/password-strength-checker.git
cd password-strength-checker
```

## How To Run

1. Install Python from [python.org](https://www.python.org/downloads/)
2. During installation, enable `Add Python to PATH`
3. Clone this repository to your local device
4. Open a terminal in the project folder
5. Run:

```bash
python app.py
```

6. Open your browser at:

```text
http://127.0.0.1:8000
```

## How It Works

The checker evaluates passwords using a mix of heuristics, including:

- password length
- character diversity
- common attacker-first patterns
- repeated characters
- date-like fragments
- keyboard or numeric sequences

The app then returns:

- a score out of 100
- a rating label
- entropy estimate
- scenario-based crack-time estimates
- findings and improvement recommendations

## Security Note

This tool is intended for educational and local analysis purposes. It does not claim to replace professional password auditing or enterprise-grade security review. Passwords are analyzed locally by the app you run on your own machine.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
