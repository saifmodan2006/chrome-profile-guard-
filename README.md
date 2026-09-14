# Chrome Profile Guard

> **Lock your browsing workspace.**  
> A production-grade, privacy-first Chrome extension that provides a dedicated password or PIN protection layer for your Chrome browsing session.

---

> [!IMPORTANT]
> **Important Architectural Limitation:**  
> **This extension provides a browsing-workspace lock.** Chrome extensions cannot replace or modify Chrome's native profile-picker authentication, internal startup security, or operating-system-level controls. It protects your browsing workspace **after** Chrome is running to prevent casual access when you step away from your device.

---

## Table of Contents
- [Overview](#overview)
- [Key Features](#key-features)
- [Security Architecture](#security-architecture)
- [Threat Model & Boundaries](#threat-model--boundaries)
- [Permissions Transparency](#permissions-transparency)
- [Privacy Model](#privacy-model)
- [Project Architecture](#project-architecture)
- [Installation & Setup](#installation--setup)
- [Development & Testing](#development--testing)
- [Future Roadmap](#future-roadmap)
- [License](#license)

---

## Overview

Modern web browsers carry our most sensitive workflows: emails, personal and corporate documents, code repositories, cloud dashboards, and chat sessions. Leaving an unlocked laptop unattended in an office, cafe, or shared workspace exposes everything in seconds.

**Chrome Profile Guard** acts as an on-device digital deadbolt for your browser. It guards your active tabs, redirects sensitive navigations, and requires cryptographic PIN or password verification before access is granted.

Designed strictly around Chrome Extension **Manifest V3** standards, Chrome Profile Guard operates **100% locally** using the standard **Web Crypto API** with zero external network requests, analytics, or third-party servers.

---

## Key Features

### 🔐 Multi-Tiered Credential Protection
- **Fast 6-Digit PIN:** Optimized for quick day-to-day unlocking with built-in blocklists for predictable combinations (`1234`, `0000`, `1111`, sequential patterns).
- **Strong Password:** For shared environments or higher security requirements, featuring a live zxcvbn-style strength meter and visibility toggles.
- **Zero Plaintext Storage:** Passwords and PINs are hashed using salted PBKDF2-HMAC-SHA256 with 210,000 iterations. The original credential never touches memory after hashing and is never written to disk.

### ⏱️ Smart Auto-Lock & Session Inactivity
- **Inactivity Timer:** Configurable timeout (1 min, 5 min default, 15 min, 30 min, 1 hour, or Never) driven by the native `chrome.idle` API.
- **OS Lock Detection:** Automatically locks the workspace the instant your operating system enters a locked state.
- **Browser Restart Auto-Lock:** Session authentication flags reside strictly in volatile `chrome.storage.session`. When Chrome closes or crashes, the session flag instantly evaporates—ensuring the browser starts up locked every single time.

### 🛡️ Multi-Layer Defense-in-Depth
1. **Layer 1 (State Engine):** Deterministic state machine (`SETUP_REQUIRED`, `LOCKED`, `UNLOCKING`, `UNLOCKED`, `TEMPORARILY_LOCKED`).
2. **Layer 2 (Tab Monitoring):** Real-time monitoring across windows and tabs via `chrome.tabs`.
3. **Layer 3 (Navigation Redirection):** Blocks outbound requests to protected domains in `chrome.webNavigation.onBeforeNavigate` and displays the dedicated lock screen.
4. **Layer 4 (Content Guard Overlay):** Uses a clean Shadow DOM barrier to immediately obscure already-open tabs when locked, preserving existing form state and scroll positions for when you unlock.
5. **Layer 5 (Settings Gate):** Configuration and credential-modification interfaces are themselves locked behind authentication.
6. **Layer 6 (Brute-Force Rate Limiter):** Exponential backoff protection (attempts 1–4 retry freely; 5th triggers 10s cooldown, escalating to 30s, 1m, 5m, and 15m plateaus).

### 🌐 Flexible Protection Scope
- **Protect Everything:** Every normal HTTP/HTTPS website requires an unlocked session.
- **Protect Selected Websites:** Specify exact sensitive domains (e.g., `mail.google.com`, `github.com`, `notion.so`). Subdomains are automatically covered.
- **Safe Exceptions Engine:** Internal schemes (`chrome://`, `chrome-extension://`, `about:`, `devtools:`) are strictly bypassed to prevent recursive redirection loops.

### ⚡ Quick-Lock Keyboard Shortcut
- Instantly lock your workspace via keyboard with **`Ctrl + Shift + L`** (Windows/Linux) or **`Command + Shift + L`** (macOS).

---

## Security Architecture

```
User Credential (PIN / Password)
               │
               ▼
   16-byte Cryptographic Salt (crypto.getRandomValues)
               │
               ▼
  PBKDF2-HMAC-SHA256 (210,000 iterations — OWASP Recommended)
               │
               ▼
   256-bit Derived Authentication Key
               │
               ▼
Persisted in chrome.storage.local (Salt + Derived Key only)
```

- **No Plaintext Storage:** The raw password or PIN is never stored in persistent storage or session memory.
- **Constant-Time Verification:** Verification compares the newly derived hash with the stored hash using a non-short-circuiting byte-by-byte comparison (`constantTimeEqual`) to defeat timing attacks.
- **Zero Information Leaks:** Lockout error messages never indicate whether a guess was "close" or partially correct.

---

## Threat Model & Boundaries

Understanding the explicit security boundaries of browser extensions is critical for high-trust software:

### What Chrome Profile Guard Protects Against:
- ✅ **Casual Access:** Colleagues, roommates, visitors, or family members opening your browser when you step away.
- ✅ **Accidental Exposure:** Leaving sensitive customer data, personal emails, or repos open on screen.
- ✅ **Quick Browsing Intrusions:** Anyone launching your browser profile to inspect tabs, history, or active sessions.

### What Chrome Profile Guard Does NOT Protect Against:
- ❌ **Operating System Administrators:** Anyone with root/administrator access to the host computer can inspect the Chrome profile directory or dump memory.
- ❌ **Extension Tampering / Uninstallation:** A malicious actor with access to your computer can disable or remove Chrome extensions via Chrome flags, settings, or CLI flags.
- ❌ **Native Profile Picker Bypass:** Chrome extensions load **after** the browser and profile start. They cannot intercept the native profile selector.
- ❌ **Forensic Attacks / Malware:** Keyloggers, spyware, or raw disk extraction require full-disk encryption (BitLocker / FileVault) and OS-level authentication.

---

## Permissions Transparency

Chrome Profile Guard adheres to the principle of least privilege. Every declared permission serves an explicit, non-bypassable architectural role:

| Permission | Purpose | Why It Cannot Be Avoided |
| :--- | :--- | :--- |
| `storage` | Persistent settings & session state | Stores the hashed credential and configuration locally; manages the volatile session unlock state in `storage.session`. |
| `idle` | Inactivity detection | Detects user absence and OS lock events to trigger automatic locking. |
| `webNavigation` | Navigation interceptor | Redirects protected web navigations to the lock screen before page rendering begins. |
| `tabs` | Tab management | Queries open tabs to apply lock screens and restore target URLs after unlocking. |
| `scripting` | Defense-in-depth content injection | Injects the Shadow DOM privacy shield into tabs opened before extension installation. |
| `host_permissions` (`http://*/*`, `https://*/*`) | Domain gating | Allows navigation monitoring and overlay shielding for web pages. Never accesses internal browser URLs. |

**No unnecessary permissions requested:** Chrome Profile Guard does **not** request `cookies`, `history`, `webRequest`, or `management`.

---

## Privacy Model

- **Zero Cloud Communication:** No remote API calls, no backend database, no telemetry, and no analytics.
- **Local Activity Logging:** Features an optional, rolling 100-event activity log (`locked`, `unlocked`, `failed_auth`, etc.). This log records timestamps only and **never** records URLs, page titles, or credential inputs. Users can disable or clear this log at any time in Settings.
- **Incognito Isolation:** Does not run in Incognito windows by default unless explicitly granted permission by the user in Chrome settings and enabled in Profile Guard preferences.

---

## Project Architecture

```
chrome-profile-guard/
├── manifest.json                  # Manifest V3 configuration & commands
├── background/
│   └── service-worker.js         # Event-driven background service worker
├── pages/
│   ├── setup/                    # 3-step first-run onboarding wizard
│   ├── lock/                     # Dedicated full-tab lock screen
│   ├── settings/                 # Comprehensive options & security dashboard
│   └── reset/                    # Irreversible credential reset flow
├── popup/
│   ├── popup.html                # Compact toolbar popup
│   ├── popup.js                  # Quick lock / inline unlock controller
│   └── popup.css                 # Clean neutral styles
├── content/
│   ├── guard.js                  # Shadow DOM tab-shielding overlay
│   └── guard.css                 # Page visibility protection (Privacy Mode)
├── shared/
│   ├── crypto.js                 # Web Crypto API key derivation & timing protection
│   ├── storage.js                # Type-safe wrappers for chrome.storage
│   ├── auth.js                   # Credential verification & progressive lockout logic
│   ├── lock-state.js             # Central lock-state machine & URL scoping
│   ├── messaging.js              # Typed Promise-based runtime messaging bridge
│   ├── constants.js              # Single source of truth for constants & enums
│   └── ui.css                    # Unified Chrome/Google aesthetic design tokens
├── icons/                        # Hand-crafted 16px, 32px, 48px, 128px PNG icons
├── scripts/
│   └── generate-icons.mjs        # Dependency-free icon generator script
├── tests/
│   ├── chrome-mock.mjs           # In-memory mock of Chrome extension storage APIs
│   └── run-tests.mjs             # 72-test automated verification suite
└── README.md                     # Technical documentation & usage guide
```

---

## Installation & Setup

### Installing as an Unpacked Extension in Chrome

1. Clone or download this repository to your local machine:
   ```bash
   git clone https://github.com/your-username/chrome-profile-guard.git
   ```
2. Open Google Chrome and navigate to `chrome://extensions/`.
3. Enable **Developer mode** in the upper right corner.
4. Click **Load unpacked** in the top left.
5. Select the `Chrome_Profile_Guard` root folder containing `manifest.json`.
6. Chrome Profile Guard will load and automatically launch the first-time onboarding screen!

---

## Development & Testing

### Running the Test Suite
The project includes a dependency-free test suite covering cryptography, storage resilience, lockout scheduling, scoping rules, and packaging integrity:

```bash
node tests/run-tests.mjs
```

Expected output:
```text
--------------------------------------------------
  72 passed, 0 failed  (72 total)
--------------------------------------------------
```

### Regenerating Extension Icons
To re-rasterize the PNG icon set from the mathematical vector definitions:
```bash
node scripts/generate-icons.mjs
```

---

## Future Roadmap

- **Multi-Workspace Profiles (V2):** Partition rules into separate workspaces (e.g., *Personal*, *Work*, *Client Work*) with distinct credentials and domain lists.
- **Native Desktop Companion (V2.5):** An optional native host utility using Chrome Native Messaging to provide operating-system-level process protection.
- **Biometric Integration:** Support for WebAuthn/FIDO2 (Touch ID, Windows Hello) hardware token unlocking where browser policies permit.

---

## License

MIT License. Designed and built with a focus on privacy, simplicity, and verifiable on-device security.
