# Contributing to VERITAS Framework

Thank you for considering contributing to VERITAS! We welcome pull requests, bug reports, feature requests, and code reviews from the cybersecurity and wireless security community.

---

## 📜 Code of Conduct

- **Ethical Integrity**: Contributions must strictly align with ethical penetration testing, defense research, and educational purposes.
- **Respect & Professionalism**: Maintain respectful communication in all issues, discussions, and pull requests.

---

## 🛠️ How to Contribute

### 1. Reporting Bugs
Before submitting a new issue, please check existing issues to avoid duplicates. When filing a bug report:
- Include your **Linux Distribution** and **Kernel Version** (`uname -r`).
- Specify your **Wireless Adapter Model** and chipset driver (e.g., `rtl8812au`, `ath9k`).
- Include steps to reproduce the issue along with compiler output or error tracebacks.

### 2. Submitting Pull Requests (PRs)
- **Fork** the repository and create a feature branch (`git checkout -b feature/amazing-feature`).
- Ensure code adheres to **C11 standards** and compiles cleanly without warnings:
  ```bash
  gcc -Wall -Wextra -O2 -pthread -std=c11 -o veritas veritas.c -lm
  ```
- Test memory safety using GCC sanitizers before submitting:
  ```bash
  gcc -Wall -Wextra -g -O0 -pthread -std=c11 -fsanitize=address,undefined -o veritas_test veritas.c -lm
  ```
- Keep pull requests focused on a single logical change or bug fix.

---

## 🧪 Coding Style Guidelines

- Use standard 2-space or 4-space indentation for C files.
- Keep function signatures explicit and include proper error handling for all system/socket calls.
- Avoid external non-standard library dependencies to maintain bare-metal execution portability.

---

## ⚖️ Contributor License Agreement

By contributing to this repository, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).
