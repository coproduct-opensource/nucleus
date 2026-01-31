import crypto from "crypto";

export type SignedHeaders = {
  "x-nucleus-timestamp": string;
  "x-nucleus-signature": string;
  "x-nucleus-actor"?: string;
  "x-nucleus-method"?: string;
};

export function signHttpHeaders(
  secret: string,
  body: string | Buffer,
  actor?: string
): SignedHeaders {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const actorValue = actor ?? "";
  const bodyBytes = typeof body === "string" ? Buffer.from(body) : body;
  const message = Buffer.concat([
    Buffer.from(timestamp),
    Buffer.from("."),
    Buffer.from(actorValue),
    Buffer.from("."),
    bodyBytes,
  ]);

  const signature = crypto
    .createHmac("sha256", secret)
    .update(message)
    .digest("hex");

  const headers: SignedHeaders = {
    "x-nucleus-timestamp": timestamp,
    "x-nucleus-signature": signature,
  };

  if (actorValue) {
    headers["x-nucleus-actor"] = actorValue;
  }

  return headers;
}

export function signGrpcHeaders(
  secret: string,
  method: string,
  actor?: string
): SignedHeaders {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const actorValue = actor ?? "";
  const message = `${timestamp}.${actorValue}.${method}`;
  const signature = crypto
    .createHmac("sha256", secret)
    .update(message)
    .digest("hex");

  const headers: SignedHeaders = {
    "x-nucleus-timestamp": timestamp,
    "x-nucleus-signature": signature,
    "x-nucleus-method": method,
  };

  if (actorValue) {
    headers["x-nucleus-actor"] = actorValue;
  }

  return headers;
}
