import { spawn } from "node:child_process";
import { mkdir, rename, rm } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { chromium } from "../web/node_modules/playwright/index.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const outputDirectory = path.join(root, "artifacts");
const outputPath = path.join(outputDirectory, "SiliconSentinel-comprehensive-demo.webm");
const python = path.join(root, ".venv", "Scripts", "python.exe");
const password = "video-demo-password";
const edgePort = 8101;
const dashboardPort = 8100;
const children = [];

const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

async function waitFor(url) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      // The child process is still starting.
    }
    await delay(250);
  }
  throw new Error(`Timed out waiting for ${url}`);
}

function start(module, port, environment) {
  const child = spawn(
    python,
    [
      "-m",
      "uvicorn",
      module,
      "--factory",
      "--host",
      "127.0.0.1",
      "--port",
      String(port),
      "--workers",
      "1",
      "--no-access-log",
    ],
    {
      cwd: root,
      env: { ...process.env, ...environment },
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    },
  );
  child.stdout.on("data", (chunk) => process.stdout.write(chunk));
  child.stderr.on("data", (chunk) => process.stderr.write(chunk));
  children.push(child);
}

async function caption(page, title, body, milliseconds = 3200) {
  await page.evaluate(
    ({ title, body }) => {
      document.querySelector("#demo-caption")?.remove();
      const caption = document.createElement("aside");
      caption.id = "demo-caption";
      caption.innerHTML = `<strong>${title}</strong><span>${body}</span>`;
      Object.assign(caption.style, {
        position: "fixed",
        zIndex: "99999",
        left: "50%",
        bottom: "26px",
        transform: "translateX(-50%)",
        width: "min(900px, calc(100% - 48px))",
        padding: "15px 20px",
        border: "1px solid #76cbb0",
        borderRadius: "9px",
        background: "rgba(8, 17, 24, .95)",
        color: "#dbe6ef",
        boxShadow: "0 15px 45px rgba(0,0,0,.45)",
        fontFamily: "Inter, Segoe UI, sans-serif",
        pointerEvents: "none",
      });
      const strong = caption.querySelector("strong");
      const span = caption.querySelector("span");
      Object.assign(strong.style, {
        display: "block",
        color: "#8ddbc0",
        fontSize: "15px",
        marginBottom: "4px",
      });
      Object.assign(span.style, { display: "block", fontSize: "13px", lineHeight: "1.5" });
      document.body.append(caption);
    },
    { title, body },
  );
  await delay(milliseconds);
}

async function main() {
  await mkdir(outputDirectory, { recursive: true });
  const shared = {
    EDGE_API_KEY: "recording-only-edge-key-123456789",
    LANGSMITH_TRACING: "false",
    LANGCHAIN_TRACING_V2: "false",
    PYTHONUNBUFFERED: "1",
  };
  start("edge.app:create_app", edgePort, {
    ...shared,
    TARGET_BACKEND: "mock",
  });
  await waitFor(`http://127.0.0.1:${edgePort}/healthz`);
  start("orchestrator.app:create_app", dashboardPort, {
    ...shared,
    EDGE_API_URL: `http://127.0.0.1:${edgePort}`,
    DASHBOARD_PASSWORD: password,
    INFERENCE_BACKEND: "scripted",
    PUBLIC_ORIGIN: `http://127.0.0.1:${dashboardPort}`,
  });
  await waitFor(`http://127.0.0.1:${dashboardPort}/healthz`);

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1600, height: 900 },
    recordVideo: { dir: outputDirectory, size: { width: 1600, height: 900 } },
    acceptDownloads: true,
  });
  const page = await context.newPage();

  await page.setContent(`<!doctype html><html><head><style>
    *{box-sizing:border-box}body{margin:0;background:#091119;color:#dbe6ef;font-family:Inter,Segoe UI,sans-serif}
    main{height:900px;padding:72px 90px;display:grid;grid-template-columns:1.1fr .9fr;gap:55px;align-items:center}
    .eyebrow{color:#75cbb0;letter-spacing:3px;font-size:14px}h1{font-size:58px;line-height:1.05;margin:18px 0 24px}
    p{color:#94a9b8;font-size:21px;line-height:1.55}.terminal{background:#060b10;border:1px solid #2b4351;border-radius:12px;padding:26px;min-height:395px;box-shadow:0 28px 80px #0008;font:17px/1.8 Consolas,monospace}
    .terminal small{display:block;color:#718594;font:12px Inter,Segoe UI,sans-serif;letter-spacing:1.4px;margin-bottom:13px}.prompt{color:#8ddbc0}.cursor{display:inline-block;width:9px;height:20px;background:#8ddbc0;vertical-align:-4px;animation:blink .75s steps(1) infinite}.output{opacity:0;transform:translateY(4px);transition:.35s}.output.show{opacity:1;transform:none}.ok{color:#8ebfe0}.architecture{display:grid;gap:12px}.architecture div{border-left:3px solid #76cbb0;background:#101e28;padding:18px;font-size:18px}.architecture small{display:block;color:#8196a8;margin-top:5px}@keyframes blink{50%{opacity:0}}
  </style></head><body><main><section><div class="eyebrow">SILICONSENTINEL · COMPLETE WORKFLOW</div><h1>Evidence-first embedded security auditing</h1><p>From one local command to bounded JTAG evidence, verified AI findings, UART assessment, and exportable reports.</p><div class="architecture"><div>1 · Edge bridge<small>OpenOCD / mock target with strict read policy</small></div><div>2 · LangGraph orchestrator<small>Planner, policy gate, collector, analyzer, verifier</small></div><div>3 · Operator dashboard<small>Live evidence, history, recovery, and reports</small></div></div></section><section class="terminal"><small>COMMAND USED IN THIS SAFE RECORDING</small><span class="prompt">PS C:\\project&gt;</span> <span id="command"></span><span class="cursor"></span><br><br><div class="output" id="build"><span class="ok">✓ Dashboard built</span></div><div class="output" id="edge"><span class="ok">✓ Edge API ready</span> · 127.0.0.1:8001</div><div class="output" id="orchestrator"><span class="ok">✓ Orchestrator ready</span> · 127.0.0.1:8000</div><div class="output" id="open"><br>Open: http://127.0.0.1:8000<br>Mode: mock + scripted</div></section></main></body></html>`);
  await delay(1800);
  const command = "uv run python scripts/demo.py";
  for (const character of command) {
    await page.locator("#command").evaluate((element, value) => { element.textContent += value; }, character);
    await delay(55);
  }
  await page.keyboard.press("Enter");
  for (const id of ["build", "edge", "orchestrator", "open"]) {
    await page.locator(`#${id}`).evaluate((element) => element.classList.add("show"));
    await delay(850);
  }
  await delay(2200);

  await page.goto(`http://127.0.0.1:${dashboardPort}`, { waitUntil: "networkidle" });
  await caption(page, "1 · Secure operator access", "The dashboard requires the per-process password printed by the launcher. API keys never enter the browser.");
  await page.getByLabel("Operator password").fill(password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await page.getByText("MOCK TARGET", { exact: true }).waitFor();

  await caption(page, "2 · Readiness before action", "Edge, CPU target, UART, and inference state are visible before an audit starts. This recording uses safe synthetic evidence.", 4200);
  await page.getByText("Run history", { exact: true }).scrollIntoViewIfNeeded();
  await caption(page, "3 · Explicit scope and bounded memory", "The operator chooses an approved region and byte budget. Excluded ranges cannot be selected, and the memory map distinguishes configured from inspected data.", 4200);

  await page.getByRole("button", { name: "Start audit", exact: true }).click();
  await caption(page, "4 · Autonomous but constrained", "LangGraph plans each read; the policy gate validates it before the edge collector touches the target. Capture and analysis limits prevent unbounded polling.", 4000);
  await page.getByRole("heading", { name: "Captured printable string" }).first().waitFor({ timeout: 15_000 });

  await page.getByRole("heading", { name: "Memory inspector" }).scrollIntoViewIfNeeded();
  await caption(page, "5 · Attributed hardware evidence", "Each capture includes its address, length, target state, timestamp, SHA-256 hash, decoded instructions, strings, and register snapshot.", 4500);
  await page.getByLabel("Evidence capture").selectOption({ index: 1 });
  await delay(2600);

  await page.getByRole("heading", { name: "Findings", exact: true }).scrollIntoViewIfNeeded();
  await caption(page, "6 · Findings must cite evidence", "The verifier checks evidence IDs and addresses. Unsupported or contradictory model claims are preserved separately as rejected—not silently promoted to vulnerabilities.", 5000);
  await page.getByRole("button", { name: /Evidence / }).first().click();
  await delay(2200);

  await page.getByText("Run history", { exact: true }).scrollIntoViewIfNeeded();
  await caption(page, "7 · Retained history and provider usage", "Runs remain in process memory for one hour. Token usage and optional operator-supplied price estimates make paid inference visible.", 4200);

  await page.getByRole("button", { name: "Attack Lab", exact: true }).click();
  await page.getByRole("heading", { name: "Attack Lab", exact: true }).waitFor();
  await caption(page, "8 · Evidence-driven attack recommendations", "The model may select only typed JTAG, debug-interface, firmware, fault-injection, or side-channel modules supported by the target profile and retained evidence.", 4200);
  await page.getByLabel("Security research instruction").fill("Assess JTAG debug lock and halt exposure");
  await page.getByRole("button", { name: "Get model recommendations" }).click();
  await page.getByRole("checkbox").check();
  await page.getByRole("button", { name: "Create HITL plan" }).click();
  await caption(page, "9 · Human-in-the-Loop gates", "The operator reviews prerequisites and approves each sensitive step. Pause, resume, rejection, and emergency abort decisions are recorded in the plan log.", 4200);
  await page.getByRole("button", { name: "Execute next approved step" }).click();
  await page.getByRole("button", { name: "Execute next approved step" }).click();
  await page.getByRole("button", { name: "Approve step" }).click();
  await page.getByRole("button", { name: "Execute next approved step" }).click();
  await caption(page, "10 · Safe execution boundary", "Evidence review executes locally. State-changing, firmware, glitch, and acquisition steps remain dry-run designs until dedicated authorized hardware adapters exist.", 4200);
  await page.getByRole("button", { name: "Investigation", exact: true }).click();

  await page.getByRole("heading", { name: "Boot and console assessment" }).scrollIntoViewIfNeeded();
  await caption(page, "11 · Fixed UART security checks", "Live mode supports passive boot capture, one U-Boot interruption attempt, or a bounded configured-account check. Credentials remain at the local edge.", 4500);

  await page.getByRole("button", { name: "Delete run from memory" }).scrollIntoViewIfNeeded();
  await page.getByRole("button", { name: "Delete run from memory" }).click();
  await caption(page, "12 · Evidence lifecycle controls", "Deletion requires explicit confirmation and recommends exporting first. Markdown and JSON reports remain operator-managed.", 4000);
  await page.getByRole("button", { name: "Keep run" }).click();

  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await page.getByRole("heading", { name: "Inspect with evidence." }).waitFor();
  await caption(page, "13 · Session closed", "Sign out invalidates the authenticated cookie and clears dashboard evidence state.", 3500);

  await page.setContent(`<!doctype html><html><head><style>*{box-sizing:border-box}body{margin:0;background:#091119;color:#dbe6ef;display:grid;place-items:center;height:900px;font-family:Inter,Segoe UI,sans-serif;text-align:center}.mark{width:86px;height:86px;margin:auto;display:grid;place-items:center;border:2px solid #76cbb0;border-radius:18px;color:#76cbb0;font-size:50px}h1{font-size:52px;margin:26px 0 12px}p{font-size:21px;color:#94a9b8;max-width:900px;line-height:1.6}.safe{margin-top:34px;color:#8ddbc0;font-size:16px;letter-spacing:2px}</style></head><body><main><div class="mark">S</div><h1>SiliconSentinel</h1><p>Physical evidence in. Bounded AI reasoning. Verifiable security findings out.</p><div class="safe">JTAG · LANGGRAPH · NVIDIA / NEBIUS · FASTAPI</div></main></body></html>`);
  await delay(6500);

  const video = page.video();
  await context.close();
  await browser.close();
  if (!video) throw new Error("Playwright did not create a video");
  const temporaryPath = await video.path();
  await rm(outputPath, { force: true });
  await rename(temporaryPath, outputPath);
  process.stdout.write(`\nCreated ${outputPath}\n`);
}

try {
  await main();
} finally {
  for (const child of children) child.kill();
}
