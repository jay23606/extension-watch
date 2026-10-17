"""Extension Watch UI QA: landing, scan of 4 real extensions, watchlist page, methodology. Real browser, real data."""
import sys
from playwright.sync_api import sync_playwright
base, out = sys.argv[1], sys.argv[2]
ids = "aapbdbdomjkkjkaonfhkkikfgjllcleb\nhttps://chromewebstore.google.com/detail/bitwarden/nngceckbapebfimnlniiiahkandclblb\nddkjiahejlhfcafbddmgiahcphecmpfh\nnot-an-id"
with sync_playwright() as p:
    b = p.chromium.connect_over_cdp("http://127.0.0.1:9341")
    for w, h, tag in ((1280, 900, "1280"), (390, 844, "390")):
        ctx = b.new_context(viewport={"width": w, "height": h}, device_scale_factor=2)
        page = ctx.new_page(); errs = []
        page.on("pageerror", lambda e: errs.append(str(e)))
        page.goto(base + "/", wait_until="networkidle")
        page.screenshot(path=f"{out}/01-landing-{tag}.png", full_page=True)
        page.fill("#tryInput", ids); page.locator("#tryForm button[type=submit]").click()
        page.wait_for_function("document.querySelector('#resultsTbody') && document.querySelector('#resultsTbody').innerText.includes('Bitwarden')", timeout=60000)
        page.wait_for_timeout(500)
        page.screenshot(path=f"{out}/02-scan-{tag}.png", full_page=True)
        print(tag, "rows:", page.locator("#resultsTbody tr").count(), "| overflow:", page.evaluate("document.documentElement.scrollWidth > window.innerWidth"), "| errors:", errs[:2])
        if tag == "1280":
            page.fill("#watchName", "Design team"); page.locator("#watchForm button[type=submit]").click()
            page.wait_for_function("location.pathname.startsWith('/w/') || document.querySelector('#watchStatus').innerText.length > 5", timeout=60000)
            page.wait_for_timeout(1500)
            print("after watch:", page.url[:60], "|", page.inner_text("#watchStatus")[:120] if page.locator("#watchStatus").count() else "")
            page.screenshot(path=f"{out}/03-watchlist-{tag}.png", full_page=True)
        ctx.close()
