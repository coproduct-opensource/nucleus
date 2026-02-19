import crypto from "crypto";

const PLUGIN_ID = "nucleus";
const DEFAULT_TIMEOUT_MS = 30_000;

type PermissionDimension =
  | "filesystem"
  | "command_exec"
  | "network_egress"
  | "approval";
type TrustTier = "unverified" | "community" | "verified" | "platform";

interface PermissionBid {
  skill_id: string;
  requested: PermissionDimension[];
  value_estimate: number;
  trust_tier: TrustTier;
}

/** Map a tool-proxy endpoint path to its permission dimension. */
function dimensionForEndpoint(path: string): PermissionDimension | null {
  switch (path) {
    case "/v1/read":
    case "/v1/write":
    case "/v1/glob":
    case "/v1/grep":
      return "filesystem";
    case "/v1/run":
      return "command_exec";
    case "/v1/web_fetch":
    case "/v1/web_search":
      return "network_egress";
    case "/v1/approve":
      return "approval";
    default:
      return null;
  }
}

interface PluginConfig {
  proxyUrl: string;
  authSecret: string;
  approvalSecret: string;
  actor: string;
  approvalTtlSecs: number;
  timeoutMs: number;
}

function getConfig(api: any): PluginConfig {
  const cfg = api?.config?.plugins?.entries?.[PLUGIN_ID]?.config ?? {};
  return {
    proxyUrl: cfg.proxyUrl ?? "http://127.0.0.1:8080",
    authSecret: cfg.authSecret ?? "",
    approvalSecret: cfg.approvalSecret ?? "",
    actor: cfg.actor ?? "",
    approvalTtlSecs:
      typeof cfg.approvalTtlSecs === "number" && cfg.approvalTtlSecs > 0
        ? cfg.approvalTtlSecs
        : 300,
    timeoutMs:
      typeof cfg.timeoutMs === "number" && cfg.timeoutMs > 0
        ? cfg.timeoutMs
        : DEFAULT_TIMEOUT_MS,
  };
}

function signHttpHeaders(
  secret: string,
  body: string,
  actor?: string
): Record<string, string> {
  if (!secret) {
    return {};
  }
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const actorValue = actor ?? "";
  const message = Buffer.concat([
    Buffer.from(timestamp),
    Buffer.from("."),
    Buffer.from(actorValue),
    Buffer.from("."),
    Buffer.from(body),
  ]);

  const signature = crypto
    .createHmac("sha256", secret)
    .update(message)
    .digest("hex");

  const headers: Record<string, string> = {
    "x-nucleus-timestamp": timestamp,
    "x-nucleus-signature": signature,
  };

  if (actorValue) {
    headers["x-nucleus-actor"] = actorValue;
  }

  return headers;
}

async function postJson(
  api: any,
  path: string,
  payload: Record<string, unknown>,
  overrideSecret?: string
): Promise<{ ok: boolean; status: number; body: any }> {
  const cfg = getConfig(api);
  const body = JSON.stringify(payload);
  const secret = overrideSecret ?? cfg.authSecret;
  const headers: Record<string, string> = {
    "content-type": "application/json",
    ...signHttpHeaders(secret, body, cfg.actor),
  };

  // Attach permission bid header when dimension is known
  const dim = dimensionForEndpoint(path);
  if (dim) {
    const bid: PermissionBid = {
      skill_id: PLUGIN_ID,
      requested: [dim],
      value_estimate: dim === "approval" ? 10.0 : 1.0,
      trust_tier: "community",
    };
    headers["x-nucleus-permission-bid"] = JSON.stringify(bid);
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), cfg.timeoutMs);
  try {
    const response = await fetch(`${cfg.proxyUrl}${path}`, {
      method: "POST",
      headers,
      body,
      signal: controller.signal,
    });
    const text = await response.text();
    let data: any = text;
    try {
      data = JSON.parse(text);
    } catch {
      // keep raw text
    }

    return { ok: response.ok, status: response.status, body: data };
  } finally {
    clearTimeout(timeout);
  }
}

function toTextResult(result: any): {
  content: [{ type: "text"; text: string }];
} {
  return {
    content: [
      {
        type: "text",
        text:
          typeof result === "string"
            ? result
            : JSON.stringify(result, null, 2),
      },
    ],
  };
}

// ---------------------------------------------------------------------------
// Plugin definition (OpenClaw plugin SDK object form)
// ---------------------------------------------------------------------------

export default {
  id: PLUGIN_ID,
  name: "Nucleus Tool Proxy",
  configSchema: {
    type: "object",
    additionalProperties: false,
    properties: {
      proxyUrl: {
        type: "string",
        description:
          "Base URL for nucleus-tool-proxy (e.g. http://127.0.0.1:8080)",
      },
      authSecret: {
        type: "string",
        description: "HMAC secret for signed requests",
      },
      approvalSecret: {
        type: "string",
        description:
          "Separate HMAC secret for approval operations (higher privilege)",
      },
      actor: {
        type: "string",
        description: "Actor identifier for audit logs",
      },
      approvalTtlSecs: {
        type: "number",
        description: "Approval TTL in seconds (default 300, max 300)",
      },
      timeoutMs: {
        type: "number",
        description: "Request timeout in milliseconds (default 30000)",
      },
    },
  },

  register(api: any) {
    // -- nucleus_read -------------------------------------------------------
    api.registerTool(
      {
        name: "nucleus_read",
        description:
          "Read a file inside the nucleus sandbox. Returns file contents.",
        parameters: {
          type: "object",
          additionalProperties: false,
          properties: {
            path: {
              type: "string",
              description: "File path relative to the sandbox root",
            },
          },
          required: ["path"],
        },
        execute: async (
          _id: string,
          params: Record<string, any>
        ): Promise<{ content: [{ type: "text"; text: string }] }> => {
          const result = await postJson(api, "/v1/read", {
            path: params.path,
          });
          return toTextResult(result);
        },
      },
      { optional: true }
    );

    // -- nucleus_write ------------------------------------------------------
    api.registerTool(
      {
        name: "nucleus_write",
        description:
          "Write a file inside the nucleus sandbox. Requires write permission in the active policy.",
        parameters: {
          type: "object",
          additionalProperties: false,
          properties: {
            path: {
              type: "string",
              description: "File path relative to the sandbox root",
            },
            contents: {
              type: "string",
              description: "File contents to write",
            },
          },
          required: ["path", "contents"],
        },
        execute: async (
          _id: string,
          params: Record<string, any>
        ): Promise<{ content: [{ type: "text"; text: string }] }> => {
          const result = await postJson(api, "/v1/write", {
            path: params.path,
            contents: params.contents,
          });
          return toTextResult(result);
        },
      },
      { optional: true }
    );

    // -- nucleus_run --------------------------------------------------------
    api.registerTool(
      {
        name: "nucleus_run",
        description:
          "Run a command inside the nucleus sandbox. Uses array-based args to prevent shell injection.",
        parameters: {
          type: "object",
          additionalProperties: false,
          properties: {
            args: {
              type: "array",
              items: { type: "string" },
              description:
                'Command as argument array, e.g. ["ls", "-la", "/tmp"]',
            },
            stdin: {
              type: "string",
              description: "Optional input to pass to command stdin",
            },
            directory: {
              type: "string",
              description:
                "Optional working directory (relative to sandbox root)",
            },
            timeout_seconds: {
              type: "number",
              description:
                "Optional timeout in seconds (clamped to policy limit)",
            },
          },
          required: ["args"],
        },
        execute: async (
          _id: string,
          params: Record<string, any>
        ): Promise<{ content: [{ type: "text"; text: string }] }> => {
          const payload: Record<string, unknown> = { args: params.args };
          if (params.stdin != null) payload.stdin = params.stdin;
          if (params.directory != null) payload.directory = params.directory;
          if (params.timeout_seconds != null)
            payload.timeout_seconds = params.timeout_seconds;
          const result = await postJson(api, "/v1/run", payload);
          return toTextResult(result);
        },
      },
      { optional: true }
    );

    // -- nucleus_web_fetch --------------------------------------------------
    api.registerTool(
      {
        name: "nucleus_web_fetch",
        description:
          "Fetch a URL through the nucleus network proxy. Respects network allowlist policy.",
        parameters: {
          type: "object",
          additionalProperties: false,
          properties: {
            url: {
              type: "string",
              description: "URL to fetch",
            },
            method: {
              type: "string",
              description: "HTTP method (default GET)",
            },
            headers: {
              type: "object",
              additionalProperties: { type: "string" },
              description: "Optional request headers",
            },
            body: {
              type: "string",
              description: "Optional request body",
            },
          },
          required: ["url"],
        },
        execute: async (
          _id: string,
          params: Record<string, any>
        ): Promise<{ content: [{ type: "text"; text: string }] }> => {
          const payload: Record<string, unknown> = { url: params.url };
          if (params.method != null) payload.method = params.method;
          if (params.headers != null) payload.headers = params.headers;
          if (params.body != null) payload.body = params.body;
          const result = await postJson(api, "/v1/web_fetch", payload);
          return toTextResult(result);
        },
      },
      { optional: true }
    );

    // -- nucleus_glob -------------------------------------------------------
    api.registerTool(
      {
        name: "nucleus_glob",
        description:
          "Search for files by glob pattern inside the nucleus sandbox.",
        parameters: {
          type: "object",
          additionalProperties: false,
          properties: {
            pattern: {
              type: "string",
              description: 'Glob pattern to match (e.g. "**/*.rs", "src/*.json")',
            },
            directory: {
              type: "string",
              description:
                "Optional directory to search in (relative to sandbox root)",
            },
            max_results: {
              type: "number",
              description: "Maximum number of results to return",
            },
          },
          required: ["pattern"],
        },
        execute: async (
          _id: string,
          params: Record<string, any>
        ): Promise<{ content: [{ type: "text"; text: string }] }> => {
          const payload: Record<string, unknown> = {
            pattern: params.pattern,
          };
          if (params.directory != null) payload.directory = params.directory;
          if (params.max_results != null)
            payload.max_results = params.max_results;
          const result = await postJson(api, "/v1/glob", payload);
          return toTextResult(result);
        },
      },
      { optional: true }
    );

    // -- nucleus_grep -------------------------------------------------------
    api.registerTool(
      {
        name: "nucleus_grep",
        description:
          "Search file contents by regex pattern inside the nucleus sandbox.",
        parameters: {
          type: "object",
          additionalProperties: false,
          properties: {
            pattern: {
              type: "string",
              description: "Regex pattern to search for",
            },
            path: {
              type: "string",
              description:
                "Optional file path to search in (relative to sandbox)",
            },
            glob: {
              type: "string",
              description: "Optional glob pattern to filter files",
            },
            context_lines: {
              type: "number",
              description: "Number of context lines before/after match",
            },
            max_matches: {
              type: "number",
              description: "Maximum number of matches to return",
            },
            case_insensitive: {
              type: "boolean",
              description: "Case-insensitive search (default false)",
            },
          },
          required: ["pattern"],
        },
        execute: async (
          _id: string,
          params: Record<string, any>
        ): Promise<{ content: [{ type: "text"; text: string }] }> => {
          const payload: Record<string, unknown> = {
            pattern: params.pattern,
          };
          if (params.path != null) payload.path = params.path;
          if (params.glob != null) payload.glob = params.glob;
          if (params.context_lines != null)
            payload.context_lines = params.context_lines;
          if (params.max_matches != null)
            payload.max_matches = params.max_matches;
          if (params.case_insensitive != null)
            payload.case_insensitive = params.case_insensitive;
          const result = await postJson(api, "/v1/grep", payload);
          return toTextResult(result);
        },
      },
      { optional: true }
    );

    // -- nucleus_web_search -------------------------------------------------
    api.registerTool(
      {
        name: "nucleus_web_search",
        description:
          "Search the web through the nucleus network proxy. Respects network allowlist policy.",
        parameters: {
          type: "object",
          additionalProperties: false,
          properties: {
            query: {
              type: "string",
              description: "Search query",
            },
            max_results: {
              type: "number",
              description: "Maximum number of results to return",
            },
          },
          required: ["query"],
        },
        execute: async (
          _id: string,
          params: Record<string, any>
        ): Promise<{ content: [{ type: "text"; text: string }] }> => {
          const payload: Record<string, unknown> = { query: params.query };
          if (params.max_results != null)
            payload.max_results = params.max_results;
          const result = await postJson(api, "/v1/web_search", payload);
          return toTextResult(result);
        },
      },
      { optional: true }
    );

    // -- nucleus_approve ----------------------------------------------------
    api.registerTool(
      {
        name: "nucleus_approve",
        description:
          "Pre-approve a pending operation in the nucleus sandbox. Uses the approval secret (higher privilege) when configured.",
        parameters: {
          type: "object",
          additionalProperties: false,
          properties: {
            operation: {
              type: "string",
              description: "Operation identifier to approve",
            },
            count: {
              type: "number",
              description: "Number of times to approve (default 1)",
            },
          },
          required: ["operation"],
        },
        execute: async (
          _id: string,
          params: Record<string, any>
        ): Promise<{ content: [{ type: "text"; text: string }] }> => {
          const payload: Record<string, unknown> = {
            operation: params.operation,
          };
          if (typeof params.count === "number") {
            payload.count = params.count;
          }
          const cfg = getConfig(api);
          if (cfg.approvalSecret) {
            payload.nonce = crypto.randomBytes(16).toString("hex");
            payload.expires_at_unix =
              Math.floor(Date.now() / 1000) + cfg.approvalTtlSecs;
          }
          const result = await postJson(
            api,
            "/v1/approve",
            payload,
            cfg.approvalSecret || undefined
          );
          return toTextResult(result);
        },
      },
      { optional: true }
    );
  },
};
