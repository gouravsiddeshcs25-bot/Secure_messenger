// PostToolUse (Edit|Write) hook: block secrets, XSS-prone innerHTML and overclaiming words.
// Exit 2 + stderr message => Claude must fix the file. Any internal error => exit 0.
import { readFileSync, existsSync, statSync } from "node:fs";
import { resolve, relative, sep } from "node:path";

function readStdin() {
  try { return readFileSync(0, "utf8"); } catch { return ""; }
}

try {
  const input = JSON.parse(readStdin() || "{}");
  const ti = input.tool_input || {};
  const filePath = ti.file_path || ti.path || "";
  if (!filePath) process.exit(0);

  const root = process.env.CLAUDE_PROJECT_DIR || input.cwd || process.cwd();
  const abs = resolve(root, filePath);
  const rel = relative(root, abs).split(sep).join("/");

  // Skip docs/, .claude/, anything outside the repo, and vendored third-party bundles.
  if (rel.startsWith("..") || rel.startsWith("docs/") || rel.startsWith(".claude/") ||
      rel.includes("/vendor/")) process.exit(0);
  if (!existsSync(abs) || statSync(abs).size > 2_000_000) process.exit(0);

  const lines = readFileSync(abs, "utf8").split(/\r?\n/);
  const problems = [];
  const check = (re, label) => {
    lines.forEach((line, i) => { if (re.test(line)) problems.push(`${rel}:${i + 1}: ${label}`); });
  };

  check(/\b\d{8,10}:[A-Za-z0-9_-]{35}\b/, "looks like a Telegram bot token; put it in secrets/.env");
  check(/-----BEGIN [A-Z ]*PRIVATE KEY-----/, "private key header; never commit key material");
  check(/\bsk-[A-Za-z0-9_-]{20,}/, "looks like an sk- API key");
  check(/\bghp_[A-Za-z0-9]{36}\b/, "looks like a GitHub token (ghp_)");
  check(/\bAKIA[0-9A-Z]{16}\b/, "looks like an AWS access key (AKIA)");
  check(/\b(unbreakable|military[- ]grade)\b|100% secure/i,
    "overclaiming wording; describe the real guarantee and its limits instead");

  // innerHTML fed with dynamic/message data (template interpolation, concatenation, or a bare variable).
  // v1 (frontend/legacy-insecure/) is deliberately insecure, so it is exempt.
  if (/\.(js|mjs|html)$/.test(rel) && !rel.startsWith("frontend/legacy-insecure/")) {
    check(/\.innerHTML\s*\+?=\s*(`[^`]*\$\{|.*["'`]\s*\+|[A-Za-z_$][\w$.]*\s*;?\s*$)/,
      "innerHTML with dynamic/message data (XSS risk); use textContent or createElement");
  }

  if (problems.length) {
    process.stderr.write("guard.mjs blocked this change:\n" + problems.slice(0, 20).join("\n") + "\n");
    process.exit(2);
  }
} catch {
  // never crash
}
process.exit(0);
