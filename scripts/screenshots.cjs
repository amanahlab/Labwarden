// Run by scripts/screenshots.sh inside the Playwright container, in the network
// namespace of the review dashboard. CommonJS so NODE_PATH finds playwright.
const { chromium } = require("playwright")

const BASE = "http://127.0.0.1:8080"
const WIDTHS = (process.env.WIDTHS || "1600,1024,390").split(",").map(Number)
const HEIGHT = 1000
const SCHEMES = (process.env.SCHEMES || "light,dark").split(",")

async function json(path) {
  const r = await fetch(BASE + path)
  if (!r.ok) throw new Error(`${path}: ${r.status}`)
  return r.json()
}

async function ready() {
  for (let i = 0; i < 60; i++) {
    try {
      await json("/api/v1/auth/me")
      return
    } catch {
      await new Promise((r) => setTimeout(r, 500))
    }
  }
  throw new Error("dashboard did not start")
}

async function main() {
  await ready()
  const host = (await json("/api/v1/hosts?size=1")).items?.[0]
  const vuln = (await json("/api/v1/vulnerabilities?size=1")).items?.[0]

  let routes = [
    ["overview", "/"],
    ["vulnerabilities", "/vulnerabilities"],
    ["findings", "/vulnerabilities?view=findings"],
    ["hosts", "/hosts"],
    ["scans", "/scans"],
    ["logs", "/logs"],
    ["settings", "/settings"],
    ["add-host", "/hosts?sheet=add-host"],
    ["add-image", "/settings?sheet=add-image"],
  ]
  if (host) routes.push(["host", `/hosts/${host.id}`], ["host-edit", `/hosts/${host.id}?sheet=edit`])
  if (vuln) routes.push(["vulnerability", `/vulnerabilities/${encodeURIComponent(vuln.id)}`], ["triage", `/vulnerabilities/${encodeURIComponent(vuln.id)}?sheet=triage`])
  const only = (process.env.ROUTES || "").split(",").filter(Boolean)
  if (only.length) routes = routes.filter(([name]) => only.includes(name))

  const browser = await chromium.launch()
  for (const scheme of SCHEMES) {
    for (const width of WIDTHS) {
      const ctx = await browser.newContext({ viewport: { width, height: HEIGHT }, colorScheme: scheme })
      const page = await ctx.newPage()
      page.on("pageerror", (e) => console.error(`page error: ${e.message}`))
      for (const [name, path] of routes) {
        await page.goto(BASE + path, { waitUntil: "networkidle" })
        // Data has arrived once no skeleton or spinner is left; then let the
        // chart and overlay animations finish.
        await page
          .waitForFunction(() => !document.querySelector(".chakra-skeleton, .chakra-spinner"), null, { timeout: 15000 })
          .catch(() => console.error(`${name}: still loading after 15 s`))
        await page.waitForTimeout(900)
        // The content sheet (<main>) is the scroll container: grow the window
        // until the whole page is in view.
        const hidden = await page.evaluate(() => {
          const m = document.querySelector("main")
          return m ? m.scrollHeight - m.clientHeight : 0
        })
        if (hidden > 0) {
          await page.setViewportSize({ width, height: HEIGHT + hidden })
          await page.waitForTimeout(300)
        }
        await page.screenshot({ path: `/out/${name}-${scheme}-${width}.png`, fullPage: true })
        if (hidden > 0) await page.setViewportSize({ width, height: HEIGHT })
      }
      await ctx.close()
      console.log(`${scheme} ${width}px: ${routes.length} pages`)
    }
  }
  await browser.close()
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
