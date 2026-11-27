# Lessons

One line per bug: `date: bug -> cause -> rule that prevents it`.

- 2026-11-27: `docs/RESULTS.md` was truncated after the table header and the runner crashed when piped -> `open()` and stdout used the Windows cp1252 codec, which can't encode emoji -> always pass `encoding="utf-8"` to file writes and reconfigure stdout to UTF-8 in scripts.
- 2026-11-27: After the move, the old `server.app:app` process still held port 8000 and served 500s, so the runner "connected" to the wrong server -> a stale dev server outlives the restructure -> stop old uvicorn processes before verifying (check with `netstat -ano | findstr :8000`).
- 2026-11-27: Sign-up failed with 'Failed to register public keys' -> the user's server on :8000 was still running the pre-auth code -> after backend changes, restart the server and check `/api/users` returns 401 before testing by hand.
- 2026-11-27: Open `/api/v1` routes shared tables with v2 and could read/delete v2 inboxes -> a legacy path bypassed new access control -> legacy/insecure routes must refuse v2 accounts; test the back door explicitly.
- 2026-11-27: Elements with the `hidden` attribute still showed -> a class rule like `.steps { display: grid }` overrides the browser's `[hidden]` style -> `ui.css` has `[hidden] { display: none !important; }`.
- 2026-11-27: A 404 in the console after burning a view-once message -> the message was deleted on Reveal and again on Burn -> delete through a once-only guard and check the console in the browser test.
