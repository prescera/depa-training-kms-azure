// Copyright (c) Microsoft Corporation.
// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.
//
// Endpoint wrapper and request helpers. Follows the ServiceResult pattern of
// the DEPA-inferencing KMS: handlers return a value (success) or throw an
// ApiError (failure); the wrapper turns both into a CCF response with a
// request-id header and uniform error body {"error": {"code", "message"}}.

import * as ccfapp from "@microsoft/ccf-app";
import { ccf } from "@microsoft/ccf-app/global";
import { ApiError } from "./errors";
import { LogContext, Logger } from "./logger";

export const REQUEST_ID_HEADER = "x-depa-request-id";

/** A successful response with a non-default status or extra headers. */
export class Reply<T> {
  constructor(
    public readonly body: T,
    public readonly statusCode = 200,
    public readonly headers: Record<string, string> = {},
  ) {}
}

export type Handler = (request: ccfapp.Request, log: LogContext) => unknown;

function requestIdOf(request: ccfapp.Request): string | undefined {
  const h = request.headers || {};
  const v = h[REQUEST_ID_HEADER] || h["x-request-id"] || h["x-ms-request-id"];
  return typeof v === "string" && /^[A-Za-z0-9._:-]{1,128}$/.test(v) ? v : undefined;
}

export function endpoint(name: string, handler: Handler): ccfapp.EndpointFn {
  return (request: ccfapp.Request): ccfapp.Response => {
    // Time is host-provided (untrusted) on CCF; it is enabled once per request
    // and used only for validity windows, never as a sole security control.
    ccf.enableUntrustedDateTime(true);
    const log = new LogContext().appendScope(name);
    const requestId = requestIdOf(request);
    if (requestId) log.setRequestId(requestId);
    const headers: Record<string, string> = {};
    if (requestId) headers[REQUEST_ID_HEADER] = requestId;
    try {
      const result = handler(request, log);
      if (result instanceof Reply) {
        return { statusCode: result.statusCode, headers: { ...headers, ...result.headers }, body: result.body };
      }
      return { statusCode: 200, headers, body: result };
    } catch (e) {
      if (e instanceof ApiError) {
        Logger.info(`${e.statusCode} ${e.code}: ${e.message}`, log);
        return { statusCode: e.statusCode, headers, body: { error: { code: e.code, message: e.message } } };
      }
      Logger.error(`unhandled: ${e instanceof Error ? e.message : String(e)}`, log);
      return { statusCode: 500, headers, body: { error: { code: "internal_error", message: "internal error" } } };
    }
  };
}

/** Parses the request body as JSON; 400 on malformed input. */
export function jsonBody(request: ccfapp.Request): unknown {
  let text: string;
  try {
    text = request.body.text();
  } catch {
    throw ApiError.badRequest("request body is not valid text");
  }
  if (text.length === 0) throw ApiError.badRequest("request body is required");
  try {
    return JSON.parse(text);
  } catch {
    throw ApiError.badRequest("request body is not valid JSON");
  }
}

export function pathParam(request: ccfapp.Request, name: string): string {
  const v = request.params?.[name];
  if (typeof v !== "string" || v.length === 0) throw ApiError.badRequest(`missing path parameter ${name}`);
  let decoded: string;
  try {
    decoded = decodeURIComponent(v);
  } catch {
    throw ApiError.badRequest(`malformed path parameter ${name}`);
  }
  return decoded;
}

export function queryParam(request: ccfapp.Request, name: string): string | undefined {
  if (!request.query) return undefined;
  for (const part of request.query.split("&")) {
    const eq = part.indexOf("=");
    const k = eq < 0 ? part : part.slice(0, eq);
    if (k !== name) continue;
    try {
      return decodeURIComponent((eq < 0 ? "" : part.slice(eq + 1)).replace(/\+/g, " "));
    } catch {
      throw ApiError.badRequest(`malformed query parameter ${name}`);
    }
  }
  return undefined;
}
