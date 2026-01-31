import crypto from "crypto";

const PLUGIN_ID = "nucleus";
const DEFAULT_TIMEOUT_MS = 30_000;

function getConfig(api: any) {
  const cfg = api?.config?.plugins?.entries?.[PLUGIN_ID]?.config ?? {};
  return {
    proxyUrl: cfg.proxyUrl ?? "http://127.0.0.1:8080",
    authSecret: cfg.authSecret ?? "",
    actor: cfg.actor ?? "",
    timeoutMs:
      typeof cfg.timeoutMs === "number" && cfg.timeoutMs > 0
        ? cfg.timeoutMs
        : DEFAULT_TIMEOUT_MS,
  };
}

function signHttpHeaders(secret: string, body: string, actor?: string) {
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
  payload: Record<string, unknown>
) {
  const cfg = getConfig(api);
  const body = JSON.stringify(payload);
  const headers: Record<string, string> = {
    "content-type": "application/json",
    ...signHttpHeaders(cfg.authSecret, body, cfg.actor),
  };

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

    if (!response.ok) {
      return {
        ok: false,
        status: response.status,
        body: data,
      };
    }

    return {
      ok: true,
      status: response.status,
      body: data,
    };
  } finally {
    clearTimeout(timeout);
  }
}

function toTextPayload(result: any) {
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

export default function (api: any) {
  api.registerTool(
    "nucleus_read",
    {
      description: "Read a file via nucleus-tool-proxy (enforced).",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: {
          path: { type: "string" },
        },
        required: ["path"],
      },
      optional: true,
    },
    async (input: { path: string }) => {
      const result = await postJson(api, "/v1/read", { path: input.path });
      return toTextPayload(result);
    }
  );

  api.registerTool(
    "nucleus_write",
    {
      description: "Write a file via nucleus-tool-proxy (enforced).",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: {
          path: { type: "string" },
          contents: { type: "string" },
        },
        required: ["path", "contents"],
      },
      optional: true,
    },
    async (input: { path: string; contents: string }) => {
      const result = await postJson(api, "/v1/write", {
        path: input.path,
        contents: input.contents,
      });
      return toTextPayload(result);
    }
  );

  api.registerTool(
    "nucleus_run",
    {
      description: "Run a command via nucleus-tool-proxy (enforced).",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: {
          command: { type: "string" },
        },
        required: ["command"],
      },
      optional: true,
    },
    async (input: { command: string }) => {
      const result = await postJson(api, "/v1/run", { command: input.command });
      return toTextPayload(result);
    }
  );

  api.registerTool(
    "nucleus_approve",
    {
      description: "Approve an operation via nucleus-tool-proxy.",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: {
          operation: { type: "string" },
          count: { type: "number" },
        },
        required: ["operation"],
      },
      optional: true,
    },
    async (input: { operation: string; count?: number }) => {
      const payload: Record<string, unknown> = { operation: input.operation };
      if (typeof input.count === "number") {
        payload.count = input.count;
      }
      const result = await postJson(api, "/v1/approve", payload);
      return toTextPayload(result);
    }
  );
}
