import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID } from "node:crypto";

// The workbench validates the current assignment, target scope, tool version and
// budget on every request. Pi gets no executable built-in tools in this mode.
export default function (pi) {
  const base = process.env.SECMIND_WORKBENCH_URL;
  const project = process.env.SECMIND_PROJECT_ID;
  const intent = process.env.SECMIND_INTENT_ID;
  const worker = process.env.SECMIND_WORKER_NAME;
  const attempt = process.env.SECMIND_ATTEMPT_ID;
  // Zero/unset delegates the round boundary to Dispatcher timeouts. A finite
  // operator override remains available independently of the task budget.
  const maxCalls = Number(process.env.SECMIND_MAX_TOOL_CALLS || 0);
  if (!Number.isSafeInteger(maxCalls) || maxCalls < 0) {
    throw new Error("SECMIND_MAX_TOOL_CALLS must be a nonnegative integer (0 uses round timeouts)");
  }
  let calls = 0;
  if (!base || !project || !intent || !worker) {
    throw new Error("Pi blackboard assignment is missing");
  }
  const endpoint = `${base.replace(/\/$/, "")}/api/v1/mcp/blackboard/${encodeURIComponent(project)}/${encodeURIComponent(intent)}`;

  async function request(suffix, options = {}, timeout = 15000) {
    const response = await fetch(`${endpoint}${suffix}`, { signal: AbortSignal.timeout(timeout), ...options });
    const body = await response.json();
    if (!response.ok) throw new Error(body.detail || `Blackboard HTTP ${response.status}`);
    return body;
  }

  let modelRequest;
  if (process.env.SECMIND_MODEL_BUDGET === "required") {
    if (!attempt) throw new Error("Model budget requires an attempt assignment");
    const post = (suffix, payload) => request(suffix, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ worker, attempt_id: attempt, ...payload }),
    });
    // The SDK catches hook exceptions and continues. Abort and exit before a
    // provider request when the workbench cannot reserve its budget.
    pi.on("before_provider_request", async (_event, ctx) => {
      modelRequest = randomUUID();
      try {
        try { await post("/model/reserve", { request_id: modelRequest }); }
        catch { await post("/model/reserve", { request_id: modelRequest }); }
      } catch (error) {
        ctx.abort();
        process.stderr.write(`Workbench model reservation failed: ${error.message}\n`);
        process.exit(72);
      }
    });
    pi.on("message_end", async (event, ctx) => {
      if (event.message.role !== "assistant" || !modelRequest) return;
      const usage = event.message.usage || {};
      const payload = { request_id: modelRequest, usage: {
        prompt_tokens: (usage.input || 0) + (usage.cacheRead || 0) + (usage.cacheWrite || 0),
        completion_tokens: usage.output || 0, cache_read_tokens: usage.cacheRead || 0,
      }};
      try {
        // Reuse the identity after a lost response; the endpoint is idempotent.
        try { await post("/model/complete", payload); }
        catch { await post("/model/complete", payload); }
        modelRequest = undefined;
      } catch (error) {
        ctx.abort();
        process.stderr.write(`Workbench model usage receipt failed: ${error.message}\n`);
        process.exit(72);
      }
    });
  }

  async function tools() {
    const result = await request(`/tools?worker=${encodeURIComponent(worker)}`);
    if (!Array.isArray(result.tools)) throw new Error("Invalid blackboard tool list");
    return result.tools;
  }

  pi.registerTool({
    name: "blackboard_tools",
    label: "Blackboard tools",
    description: "Discover assigned security tools. With no arguments, return a compact directory across all services. Use query to search descriptions, then tool to read one tool's full argument schema before invoking it.",
    parameters: {
      type: "object",
      properties: { query: { type: "string" }, tool: { type: "string" } },
      additionalProperties: false,
    },
    async execute(_id, params = {}) {
      const available = await tools();
      const terms = (params.query || "").toLowerCase().trim().split(/\s+/).filter(Boolean);
      const matches = available.filter((item) => params.tool
        ? item.name === params.tool
        : terms.every((term) => `${item.name} ${item.description}`.toLowerCase().includes(term)));
      const result = {
        available_count: available.length,
        tools: params.tool ? matches : matches.map(({ name, description }) => ({ name, description: String(description || "").slice(0, 240) })),
        next: params.tool ? "Use this schema with blackboard_invoke." : "Call blackboard_tools with tool set to the chosen name to get its argument schema. Choose by the current evidence and authorized scope; a tool's presence is not authorization to use it.",
      };
      return { content: [{ type: "text", text: JSON.stringify(result) }] };
    },
  });

  pi.registerTool({
    name: "blackboard_invoke",
    label: "Invoke blackboard tool",
    description: `Run an assigned security tool through the workbench. First read its schema with blackboard_tools. ${maxCalls ? `This round allows at most ${maxCalls} invocations.` : "Dispatcher controls this round's execution time; the workbench enforces the shared task budget."} Conclude with confirmed incremental results and receipt paths.`,
    parameters: {
      type: "object",
      properties: {
        tool: { type: "string" },
        arguments: { type: "object", additionalProperties: true },
      },
      required: ["tool", "arguments"],
      additionalProperties: false,
    },
    async execute(_id, params) {
      const available = await tools();
      const chosen = available.find((item) => item.name === params.tool);
      if (!chosen) throw new Error("Tool is unavailable for this intent");
      if (maxCalls && calls >= maxCalls) {
        return { content: [{ type: "text", text: "This round's tool budget is exhausted. Do not retry tool calls. Return the required final JSON now with confirmed incremental results, receipt paths and any limitations so the planner can schedule the next intent." }], isError: true };
      }
      calls += 1;
      const payload = {
        worker, tool: chosen.name, arguments: params.arguments,
        version: chosen.version, request_id: randomUUID(),
      };
      const invoke = () => request("/invoke", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      }, 610000);
      // The server keeps a durable receipt under request_id. A lost response
      // must retrieve that receipt instead of starting another tool call.
      let receipt;
      try { receipt = await invoke(); } catch { receipt = await invoke(); }
      while (receipt.approval_required || receipt.status === "running") {
        await new Promise((resolve) => setTimeout(resolve, 2000));
        if (receipt.status === "running") {
          receipt = await invoke();
          continue;
        }
        const response = await fetch(`${base.replace(/\/$/, "")}/api/v1/mcp/approvals/${encodeURIComponent(receipt.approval_id)}`, { signal: AbortSignal.timeout(15000) });
        const approval = await response.json();
        if (!response.ok) throw new Error(approval.detail || "MCP approval unavailable");
        if (approval.status === "approved") {
          receipt = await invoke();
        } else if (approval.status !== "pending") {
          throw new Error(`MCP approval ${approval.status}`);
        }
      }
      if (!/^[0-9a-f-]{36}$/i.test(receipt.call_id || "")) throw new Error("Invalid receipt id");
      const folder = join(process.cwd(), ".mcp-results");
      await mkdir(folder, { recursive: true });
      const artifact = join(folder, `${receipt.call_id}.json`);
      await writeFile(artifact, JSON.stringify(receipt, null, 2), "utf8");
      const output = receipt.result ? JSON.stringify(receipt.result) : String(receipt.error || "");
      const remaining = maxCalls - calls;
      const progress = !maxCalls ? "Round time is controlled by Dispatcher; task budget is enforced by the workbench. Conclude once an incremental fact is verified; do not repeat probes without new evidence." : remaining ? `Round budget: ${remaining} invocations remaining. Conclude early once you have verified an incremental fact; do not repeat probes without new evidence.` : "Round budget exhausted. Return the required final JSON now; no more tool calls this round.";
      const truncated = output.length > 8000 ? "\nResult preview truncated. Read the receipt file for the complete result." : "";
      return { content: [{ type: "text", text: `Receipt: ${artifact}\nStatus: ${receipt.status}\nBlackboard: ${project}/${intent}\n${progress}\n${output.slice(0, 8000)}${truncated}` }], isError: receipt.status !== "completed" };
    },
  });
}
