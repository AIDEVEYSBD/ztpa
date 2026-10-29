"""Browser walkthrough of the FRR screens (TEST-BACKLOG T1/T2, automated part).

Signs in with the break-glass credential, uploads an export through the UI,
visits every FRR screen, opens a register row, filters partly covered rules,
runs the agents, and saves screenshots. Records browser console errors, page
errors and every API response >= 400. It does not judge the screens: a person
looks at the screenshots.

    BASE_URL=http://localhost:3000 BREAKGLASS_EMAIL=... BREAKGLASS_PASSWORD=... \\
      backend/.venv/bin/python scripts/ui_walkthrough.py export.json out/ --width 1440

Needs Playwright (`pip install playwright && playwright install chromium`) and a
running frontend + API in FRR mode. Grants the signed-in admin both duties.
Exits 1 when any problem was recorded.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("export", type=Path)
    ap.add_argument("out", type=Path)
    ap.add_argument("--width", type=int, default=1440)
    a = ap.parse_args()
    base = os.environ.get("BASE_URL", "http://localhost:3000").rstrip("/")
    email, password = os.environ["BREAKGLASS_EMAIL"], os.environ["BREAKGLASS_PASSWORD"]
    shots = a.out / str(a.width)
    shots.mkdir(parents=True, exist_ok=True)
    problems: list[tuple[str, str]] = []
    doc = json.loads(a.export.read_text())
    doc["nonce"] = str(time.time())                    # a new sha256, so the upload is not a duplicate
    upload = shots / f"walkthrough-{a.width}.json"
    upload.write_text(json.dumps(doc))

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_context(viewport={"width": a.width, "height": 900}).new_page()
        page.on("console", lambda m: m.type == "error" and problems.append(("console", m.text[:300])))
        page.on("pageerror", lambda e: problems.append(("pageerror", str(e)[:300])))
        page.on("response", lambda r: r.status >= 400 and "/_next/" not in r.url
                and problems.append(("http", f"{r.status} {r.request.method} {r.url[len(base):]}")))

        def shot(name: str) -> None:
            page.wait_for_timeout(1200)
            page.screenshot(path=str(shots / f"{name}.png"), full_page=True)

        def scroll_main() -> None:                     # screens scroll inside the main panel
            page.evaluate("() => { const m = [...document.querySelectorAll('main, main *')].find(e => "
                          "e.scrollHeight > e.clientHeight + 50 && getComputedStyle(e).overflowY !== 'visible');"
                          " if (m) m.scrollTop += 850; }")

        def nav(label: str) -> None:
            page.get_by_role("button", name=label, exact=True).first.click()

        page.goto(f"{base}/login")
        shot("00-login")
        page.get_by_text("Break-glass sign-in").click()
        page.get_by_label("Break-glass email").fill(email)
        page.get_by_label("Break-glass password").fill(password)
        page.get_by_text("Break the glass").click()
        page.wait_for_url("**/console**", timeout=60000)
        for duty in ("network_owner", "security_approver"):
            r = page.request.post(f"{base}/api/admin/frr/approvers", data={"principal": email, "duty": duty})
            if r.status not in (200, 201, 409):
                problems.append(("setup", f"approver {duty}: {r.status}"))
        shot("01-console")
        nav("Exports")
        page.set_input_files("#frr-file", str(upload))
        page.get_by_role("button", name="Upload", exact=True).click()
        page.wait_for_timeout(6000)
        page.get_by_role("button", name="Refresh").first.click()
        shot("02-exports")
        page.get_by_text(upload.name).first.click()
        nav("Rule review")
        shot("03-review")
        page.locator("tbody tr").first.click()
        shot("04-review-row")
        page.get_by_role("checkbox", name="Partly covered above").click()
        if page.locator("tbody tr").count():
            page.locator("tbody tr").first.click()
        shot("05-review-partly-covered")
        page.get_by_role("checkbox", name="Partly covered above").click()
        page.get_by_role("button", name="(all gateways)").first.click()
        shot("06-effective-policy")
        nav("Change package")
        shot("07-package")
        page.get_by_role("button", name="Run agents").click()
        for _ in range(60):
            page.wait_for_timeout(3000)
            if page.get_by_text("Validate", exact=False).count() or page.get_by_text("failed", exact=False).count():
                break
        shot("08-package-after-run")
        for k in range(3):
            scroll_main()
            shot(f"09-package-scrolled-{k + 1}")
        for i, label in enumerate(("Context data", "Approvers", "Knowledge")):
            nav(label)
            shot(f"1{i}-{label.lower().replace(' ', '-')}")
        browser.close()

    (shots / "problems.json").write_text(json.dumps(problems, indent=1))
    print(f"{len(problems)} problem(s); screenshots in {shots}")
    for kind, text in problems:
        print(f"  {kind}: {text}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
