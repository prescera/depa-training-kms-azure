// Copyright (c) Microsoft Corporation.
// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.
//
// Adapted from the Azure privacy-sandbox / DEPA-inferencing KMS Logger.
// Node logs are visible to the ledger operator: never log request bodies,
// tokens, signatures or key material.

// Provided by the CCF JS runtime (and Node in unit tests).
declare const console: { log(m: string): void; warn(m: string): void; error(m: string): void };

export enum LogLevel {
  ERROR = 0,
  WARN = 1,
  INFO = 2,
  DEBUG = 3,
}

export class LogContext {
  private readonly scopes: string[] = [];
  requestId?: string;

  appendScope(scope: string): LogContext {
    this.scopes.push(scope);
    return this;
  }

  setRequestId(requestId: string): LogContext {
    this.requestId = requestId;
    return this;
  }

  toString(): string {
    const parts: string[] = [];
    if (this.requestId) parts.push(`requestId=${this.requestId}`);
    parts.push(`scope=${this.scopes.join("->")}`);
    return `[${parts.join(",")}]`;
  }
}

export class Logger {
  private static level: LogLevel = LogLevel.INFO;

  static setLogLevel(level: LogLevel): void {
    Logger.level = level;
  }

  private static emit(level: LogLevel, tag: string, message: string, ctx?: LogContext): void {
    if (Logger.level < level) return;
    const line = ctx ? `[${tag}] ${ctx.toString()} ${message}` : `[${tag}] ${message}`;
    if (level === LogLevel.ERROR) console.error(line);
    else if (level === LogLevel.WARN) console.warn(line);
    else console.log(line);
  }

  static error(message: string, ctx?: LogContext): void {
    Logger.emit(LogLevel.ERROR, "ERROR", message, ctx);
  }
  static warn(message: string, ctx?: LogContext): void {
    Logger.emit(LogLevel.WARN, "WARN", message, ctx);
  }
  static info(message: string, ctx?: LogContext): void {
    Logger.emit(LogLevel.INFO, "INFO", message, ctx);
  }
  static debug(message: string, ctx?: LogContext): void {
    Logger.emit(LogLevel.DEBUG, "DEBUG", message, ctx);
  }
}
