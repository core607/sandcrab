/// <reference types="node" />

export class SandcrabError extends Error {
  readonly status: number;
  readonly code: string;
  readonly recoveryId: string | null;
  constructor(status: number, code: string, recoveryId?: string | null);
}

export class TransportUncertainError extends Error {
  readonly operation: string;
  readonly recoveryId: string;
  constructor(operation: string, recoveryId: string, cause?: unknown);
}

export class CommandFailedError extends Error {
  readonly run: Record<string, unknown>;
  constructor(run: Record<string, unknown>);
}

export class ProtocolError extends Error {
  constructor(message: string);
}

export class PublicationUncertainError extends Error {
  readonly templateId: string;
  constructor(templateId: string);
}

export function checkUuid(value: string, label?: string): string;
export function checkDigest(value: string, label?: string): string;
export function checkProfile(value: string): string;
export function checkRelativePath(value: string, options?: { allowRoot?: boolean }): string;
export function recipeId(layers: readonly string[]): string;

export interface ReplyLedgerEntry {
  requestSha256: string;
  reply: Buffer;
}

export interface ReplyLedger {
  get(runId: string, callId: string): ReplyLedgerEntry | null | Promise<ReplyLedgerEntry | null>;
  put(runId: string, callId: string, requestSha256: string, reply: Uint8Array): void | Promise<void>;
}

export class InMemoryReplyLedger implements ReplyLedger {
  readonly size: number;
  get(runId: string, callId: string): ReplyLedgerEntry | null;
  put(runId: string, callId: string, requestSha256: string, reply: Uint8Array): void;
}

export interface CallContext {
  runId: string;
  serverId: string;
  callId: string;
  guestRequestId: string;
  sequence: number;
  requestSha256: string;
  cursor: string | null;
}

export type HostCallReplyValue = Buffer | Uint8Array | string | Record<string, unknown> | unknown[];

export class HostCallDispatcher {
  readonly ledger: ReplyLedger;
  readonly operationField: string;
  constructor(options?: { ledger?: ReplyLedger; operationField?: string });
  onCall(handler: (payload: Buffer, context: CallContext) => HostCallReplyValue | Promise<HostCallReplyValue>): this;
  onJson<T extends Record<string, unknown> = Record<string, unknown>>(
    operation: string,
    handler: (request: T, context: CallContext) => HostCallReplyValue | Promise<HostCallReplyValue>
  ): this;
  handlePayload(payload: Buffer, context: CallContext): Promise<Buffer>;
  drive(
    client: SandcrabClient,
    runId: string,
    options?: { expectedServerId?: string | null; after?: string | null }
  ): Promise<Record<string, unknown>>;
}

export type ByteRangeSpec =
  | string
  | { start: number; end?: number; suffix?: undefined }
  | { suffix: number; start?: undefined; end?: undefined };

export interface RunOptions {
  profile?: string;
  id?: string;
  timeoutMs?: number;
  outputLimitBytes?: number;
  memoryBytes?: number;
  cpuQuotaPercent?: number;
  onOutput?: (stream: "stdout" | "stderr", chunk: Buffer) => void | Promise<void>;
  dispatcher?: HostCallDispatcher;
  keepResult?: boolean;
  check?: boolean;
}

export interface SessionOpenOptions {
  profile?: string;
  id?: string;
  ttlMs?: number;
  volumeId?: string;
  templateId?: string;
  rootfs?: boolean;
  memoryBytes?: number;
  cpuQuotaPercent?: number;
  keepResult?: boolean;
  autoClose?: boolean;
}

export interface SessionExecOptions {
  id?: string;
  timeoutMs?: number;
  outputLimitBytes?: number;
  onOutput?: (stream: "stdout" | "stderr", chunk: Buffer) => void | Promise<void>;
  dispatcher?: HostCallDispatcher;
  keepResult?: boolean;
  check?: boolean;
}

export interface WriteFileOptions {
  parents?: boolean;
  replace?: boolean;
  mode?: number;
}

export interface ReadFileOptions {
  byteRange?: ByteRangeSpec;
  offset?: number;
  limit?: number;
}

export interface SandcrabClientOptions {
  socketPath?: string;
  endpoint?: string;
  token?: string;
  tokenFile?: string;
  defaultProfile?: string;
  timeoutMs?: number;
  requireSocketStat?: boolean;
  env?: Record<string, string | undefined>;
}

export class SandcrabSession {
  readonly client: SandcrabClient;
  data: Record<string, unknown>;
  readonly id: string;
  readonly serverId: string;
  readonly profile: string;
  refresh(): Promise<Record<string, unknown>>;
  renew(ttlMs: number): Promise<Record<string, unknown>>;
  exec(command: string, options?: SessionExecOptions): Promise<Record<string, unknown>>;
  openShell(options?: { id?: string; keepResult?: boolean; autoClose?: boolean }): Promise<SandcrabSession>;
  writeFile(filePath: string, data: string | Uint8Array, options?: WriteFileOptions): Promise<Record<string, unknown>>;
  readFile(filePath: string, options?: ReadFileOptions): Promise<Buffer>;
  readText(filePath: string, options?: ReadFileOptions & { encoding?: BufferEncoding }): Promise<string>;
  mkdir(dirPath: string, options?: { mode?: number }): Promise<Record<string, unknown>>;
  listFiles(dirPath?: string, options?: { depth?: number }): Promise<Array<Record<string, unknown>>>;
  searchFiles(pattern: string, options?: { path?: string }): Promise<Array<Record<string, unknown>>>;
  removeFile(filePath: string, options?: { recursive?: boolean }): Promise<Record<string, unknown>>;
  diff(): Promise<Buffer>;
  snapshot(options?: { path?: string; format?: string; frozen?: boolean; scope?: string }): Promise<Buffer>;
  close(options?: { forget?: boolean }): Promise<Record<string, unknown>>;
  forget(): Promise<Record<string, unknown>>;
  [Symbol.asyncDispose](): Promise<void>;
}

export type WorkspaceToolName = "exec" | "read_file" | "write_file" | "edit_file" | "list_dir" | "search";
export interface WorkspaceTools {
  readonly schemas: ReadonlyArray<{ name: WorkspaceToolName; description: string; inputSchema: Record<string, unknown> }>;
  readonly handlers: Record<WorkspaceToolName, (args: Record<string, unknown>) => Promise<WorkspaceToolResult>>;
  call(name: WorkspaceToolName, args: Record<string, unknown>): Promise<WorkspaceToolResult>;
  checkpoint(): Promise<Buffer>;
  dispose(): Promise<void>;
}
export interface WorkspaceToolResult {
  ok: boolean;
  code?: string;
  [field: string]: unknown;
}

export class SandcrabClient {
  workspaceTools(key: string, options?: { profile?: string; templateId?: string; freshChild?: boolean }): Promise<WorkspaceTools>;
  readonly defaultProfile: string | null;
  readonly timeoutMs: number;
  constructor(options?: SandcrabClientOptions);
  close(): void;
  info(): Promise<Record<string, unknown>>;
  openapi(capability?: string): Promise<Record<string, unknown>>;
  submitRun(command: readonly string[], options?: RunOptions): Promise<Record<string, unknown>>;
  getRun(runId: string): Promise<Record<string, unknown>>;
  listRuns(options?: { after?: string }): Promise<Record<string, unknown>>;
  cancelRun(runId: string): Promise<Record<string, unknown>>;
  forgetRun(runId: string): Promise<Record<string, unknown>>;
  waitRun(runId: string, options?: { pollIntervalMs?: number; timeoutMs?: number }): Promise<Record<string, unknown>>;
  streamEvents(runId: string, options?: { after?: string | null }): AsyncGenerator<Record<string, unknown>>;
  streamCallEvents(runId: string, options?: { after?: string | null }): AsyncGenerator<Record<string, unknown>>;
  listCalls(runId: string): Promise<Record<string, unknown>>;
  replyCall(runId: string, callId: string, reply: string | Uint8Array): Promise<Record<string, unknown>>;
  run(command: readonly string[], options?: RunOptions): Promise<Record<string, unknown>>;
  openSession(options?: SessionOpenOptions): Promise<SandcrabSession>;
  withSession<T>(fn: (session: SandcrabSession) => Promise<T>): Promise<T>;
  withSession<T>(options: SessionOpenOptions, fn: (session: SandcrabSession) => Promise<T>): Promise<T>;
  openShell(
    parentSessionId: string,
    options?: { id?: string; keepResult?: boolean; autoClose?: boolean }
  ): Promise<SandcrabSession>;
  getSession(sessionId: string): Promise<Record<string, unknown>>;
  listSessions(options?: { after?: string }): Promise<Record<string, unknown>>;
  renewSession(sessionId: string, ttlMs: number): Promise<Record<string, unknown>>;
  waitSession(
    sessionId: string,
    options?: { terminal?: boolean; pollIntervalMs?: number; timeoutMs?: number }
  ): Promise<Record<string, unknown>>;
  closeSession(sessionId: string, options?: { forget?: boolean }): Promise<Record<string, unknown>>;
  forgetSession(sessionId: string): Promise<Record<string, unknown>>;
  submitSessionCommand(sessionId: string, command: string, options?: SessionExecOptions): Promise<Record<string, unknown>>;
  sessionExec(sessionId: string, command: string, options?: SessionExecOptions): Promise<Record<string, unknown>>;
  writeFile(
    sessionId: string,
    filePath: string,
    data: string | Uint8Array,
    options?: WriteFileOptions
  ): Promise<Record<string, unknown>>;
  readFile(sessionId: string, filePath: string, options?: ReadFileOptions): Promise<Buffer>;
  mkdir(sessionId: string, dirPath: string, options?: { mode?: number }): Promise<Record<string, unknown>>;
  listFiles(sessionId: string, dirPath?: string, options?: { depth?: number }): Promise<Array<Record<string, unknown>>>;
  searchFiles(
    sessionId: string,
    pattern: string,
    options?: { path?: string }
  ): Promise<Array<Record<string, unknown>>>;
  removeFile(sessionId: string, filePath: string, options?: { recursive?: boolean }): Promise<Record<string, unknown>>;
  sessionDiff(sessionId: string): Promise<Buffer>;
  sessionSnapshot(
    sessionId: string,
    options?: { path?: string; format?: string; frozen?: boolean; scope?: string }
  ): Promise<Buffer>;
  createVolume(options?: {
    profile?: string;
    id?: string;
    cloneFrom?: string;
    byteLimit?: number;
    inodeLimit?: number;
    wait?: boolean;
  }): Promise<Record<string, unknown>>;
  getVolume(volumeId: string): Promise<Record<string, unknown>>;
  listVolumes(options?: { after?: string }): Promise<Record<string, unknown>>;
  waitVolume(
    volumeId: string,
    options?: { target?: string; pollIntervalMs?: number; timeoutMs?: number }
  ): Promise<Record<string, unknown>>;
  deleteVolume(volumeId: string, options?: { forget?: boolean }): Promise<Record<string, unknown>>;
  forgetVolume(volumeId: string): Promise<Record<string, unknown>>;
  importTemplate(
    archive: string | Uint8Array,
    options?: { profile?: string; expectedId?: string }
  ): Promise<Record<string, unknown>>;
  getTemplate(templateId: string): Promise<Record<string, unknown> | null>;
  listTemplates(options?: { after?: string }): Promise<Record<string, unknown>>;
  composeTemplate(layers: readonly string[]): Promise<Record<string, unknown>>;
  deleteTemplate(templateId: string): Promise<Record<string, unknown>>;
}
