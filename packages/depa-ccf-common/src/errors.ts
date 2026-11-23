// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.

/**
 * Error carrying an HTTP status and a stable machine-readable code. Any
 * non-2xx response produced from an ApiError discards all KV writes of the
 * transaction (CCF default), so a failed check never leaves partial state.
 */
export class ApiError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
  }

  static badRequest(message: string, code = "bad_request"): ApiError {
    return new ApiError(400, code, message);
  }
  static unauthorized(message: string, code = "unauthorized"): ApiError {
    return new ApiError(401, code, message);
  }
  static forbidden(message: string, code = "forbidden"): ApiError {
    return new ApiError(403, code, message);
  }
  static notFound(message: string, code = "not_found"): ApiError {
    return new ApiError(404, code, message);
  }
  static conflict(message: string, code = "conflict"): ApiError {
    return new ApiError(409, code, message);
  }
  static internal(message: string, code = "internal_error"): ApiError {
    return new ApiError(500, code, message);
  }
}

/** Throws a 400 ApiError unless the condition holds. */
export function require400(cond: unknown, message: string, code = "bad_request"): asserts cond {
  if (!cond) throw ApiError.badRequest(message, code);
}

/** Throws a 403 ApiError unless the condition holds. */
export function require403(cond: unknown, message: string, code = "forbidden"): asserts cond {
  if (!cond) throw ApiError.forbidden(message, code);
}
