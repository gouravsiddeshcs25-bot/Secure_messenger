// Stop hook: if code changed after plan/PROGRESS.md was last updated, ask Claude to sync the plan.
// Never crashes: any error -> exit 0.
import { readFileSync, existsSync, statSync } from "node:fs";
import { execSync } from "node:child_process";
import { join } from "node:path";

try {
  let input = {};
  try { input = JSON.parse(readFileSync(0, "utf8") || "{}"); } catch { input = {}; }
  if (input.stop_hook_active === true) process.exit(0);

  const root = process.env.CLAUDE_PROJECT_DIR || input.cwd || process.cwd();
  const progress = join(root, "plan", "PROGRESS.md");
  if (!existsSync(progress)) process.exit(0);
  const progressTime = statSync(progress).mtimeMs;

  const status = execSync("git status --porcelain --untracked-files=all", {
    cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"],
  });

  const changed = status.split(/\r?\n/).filter(Boolean).map((l) => {
    let p = l.slice(3).trim();
    if (p.includes(" -> ")) p = p.split(" -> ").pop();
    return p.replace(/^"|"$/g, "");
  });

  const stale = changed.filter((p) => {
    if (p.startsWith("plan/") || p.startsWith("docs/")) return false;
    const abs = join(root, p);
    if (!existsSync(abs)) return false; // deletions/renames-away have no mtime to compare
    try { return statSync(abs).mtimeMs > progressTime; } catch { return false; }
  });

  if (stale.length) {
    process.stderr.write(
      "Code changed but plan/PROGRESS.md was not updated: update PROGRESS.md and tick plan/TASKS.md\n" +
      "Changed: " + stale.slice(0, 10).join(", ") + (stale.length > 10 ? " ..." : "") + "\n"
    );
    process.exit(2);
  }
} catch {
  // never crash
}
process.exit(0);
