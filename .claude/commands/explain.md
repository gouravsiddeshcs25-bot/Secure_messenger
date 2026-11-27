---
description: Explain a file, concept or attack in this project for viva/demo prep, simply and accurately.
argument-hint: <file, function, concept or attack>
---
Explain: $ARGUMENTS

1. Read the actual code involved (follow imports across `backend/app/`, `frontend/shared/`, `frontend/web/`,
   `attacks/`). Base the explanation on the code, not on general knowledge.
2. Structure:
   - **What it does**, in one sentence.
   - **How it works**: step by step, with `file:line` references.
   - **Why it's secure, or why it isn't (v1)**: the property it protects and the attack it stops. Name the attack test.
   - **Limits**: what it does NOT protect against. Be honest, with no overclaiming.
   - **Likely viva questions** (3) with short answers.
3. Keep it under about 300 words unless asked for more. Don't edit any file.
