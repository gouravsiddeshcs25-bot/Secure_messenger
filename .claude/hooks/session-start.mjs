// SessionStart hook: print plan state + git state so every session starts in context.
// Never crashes: any error -> exit 0.
import { readFileSync, existsSync } from "node:fs";
import { execSync } from "node:child_process";
import { join } from "node:path";

const MAX = 9000;
try {
  const root = process.env.CLAUDE_PROJECT_DIR || process.cwd();
  const read = (rel) => {
    const p = join(root, rel);
    return existsSync(p) ? readFileSync(p, "utf8").trim() : `(missing: ${rel})`;
  };
  const git = (args) => {
    try {
      return execSync(`git ${args}`, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
    } catch {
      return "(git unavailable)";
    }
  };
  const tail = (text, n) => (text.length > n ? "...(trimmed)\n" + text.slice(-n) : text);

  const head = [
    "=== SECURE MESSENGER: SESSION CONTEXT ===",
    `Branch: ${git("rev-parse --abbrev-ref HEAD")}`,
    "",
    "--- Last 5 commits ---",
    git("log --oneline -5"),
    "",
    "--- git status ---",
    git("status --short") || "(clean)",
    "",
  ].join("\n");
  const lessons = "--- plan/LESSONS.md ---\n" + tail(read("plan/LESSONS.md"), 2500) + "\n";
  const budget = Math.max(500, MAX - head.length - lessons.length - 200);
  const progress = "--- plan/PROGRESS.md ---\n" + tail(read("plan/PROGRESS.md"), budget) + "\n";

  let out = `${head}${progress}\n${lessons}\nRules: read CLAUDE.md. Run python attacks/run_all_attacks.py after every change.`;
  if (out.length > MAX) out = out.slice(0, MAX - 20) + "\n...(truncated)";
  process.stdout.write(out + "\n");
} catch {
  // swallow
}
process.exit(0);
