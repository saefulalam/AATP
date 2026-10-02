// Provenance nodes + DAG store (blueprint §7, PRV-001..022 subset). Fresh
// logic; constants, grammars and error-code mapping copied from aatp/node.py
// (see D-021). Minimal store: add + get + ancestors + ancestryStatus with
// lazy/require parent policy and the 120s clock-skew rule.
//
// node_id = "sha256:" + hex(SHA256(D_NODE + JCS(node))) (PRV-001). Nodes are
// published as DSSE node+json envelopes signed by actor (PRV-002).

import { sha256 } from "@noble/hashes/sha2.js";
import { b64uDec, hex } from "./b64.ts";
import { jcs, parseJcs } from "./canon.ts";
import {
  PT_NODE,
  makeEnvelope,
  verifyEnvelope,
  type DsseEnvelope,
  type EnvelopeSigner,
} from "./dsse.ts";
import { AATPError, err } from "./errors.ts";

// Domain constant copied verbatim from aatp/node.py (byte-exact ASCII + \n).
export const D_NODE: Uint8Array = new TextEncoder().encode("AATP/0.2/NODE\n");

// PRV-005 clock skew, copied verbatim from aatp/node.py.
export const CLOCK_SKEW_SECONDS = 120;

// Grammars copied verbatim from aatp/node.py.
const TS_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const AGENT_RE = /^aatp:[a-z2-7]{52}$/;
const TASK_RE = /^[A-Za-z0-9_.:-]{1,128}$/;

const OPERATIONS: ReadonlySet<string> = new Set([
  "create",
  "modify",
  "merge",
  "revert",
  "verify",
  "supersede",
]);

const GENERATOR_KINDS: ReadonlySet<string> = new Set([
  "ai",
  "human",
  "tool",
  "mixed",
]);

const ASSURANCES: ReadonlySet<string> = new Set([
  "self_asserted",
  "issuer_attested",
  "hardware_attested",
]);

const RAW_PROMPT_KEYS: readonly string[] = ["prompt", "prompt_text", "toolcalls"];

export type NodeOperation =
  | "create"
  | "modify"
  | "merge"
  | "revert"
  | "verify"
  | "supersede";

export interface ProvenanceNode {
  v: string;
  content_root: string;
  parents: string[];
  operation: string;
  actor: string;
  task_id: string;
  created_at: string;
  generator?: Record<string, unknown>;
  annotations?: Record<string, unknown>;
}

export type GeneratorInput = Record<string, unknown> | null | undefined;
export type AnnotationsInput = Record<string, unknown> | null | undefined;
export type KeyResolver = (actor: string) => Uint8Array;

function malformed(detail: string): never {
  throw err("ERR_MALFORMED_MESSAGE", detail);
}

// GEN-004 strict timestamps, own parser (no Date.parse leniency): the regex
// fixes the shape, then the components must round-trip through the calendar
// (rejects month 13, Feb 30, hour 25, ...). Returns epoch milliseconds.
function parseTs(s: unknown): number {
  if (typeof s !== "string" || !TS_RE.test(s)) {
    malformed("timestamp must be YYYY-MM-DDTHH:MM:SSZ");
  }
  const y = Number(s.slice(0, 4));
  const mo = Number(s.slice(5, 7));
  const d = Number(s.slice(8, 10));
  const h = Number(s.slice(11, 13));
  const mi = Number(s.slice(14, 16));
  const se = Number(s.slice(17, 19));
  if (y < 1 || y > 9999 || mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || se > 59) {
    malformed("invalid timestamp");
  }
  const t = new Date(Date.UTC(y, mo - 1, d, h, mi, se));
  t.setUTCFullYear(y);
  if (
    t.getUTCFullYear() !== y || t.getUTCMonth() !== mo - 1 ||
    t.getUTCDate() !== d || t.getUTCHours() !== h ||
    t.getUTCMinutes() !== mi || t.getUTCSeconds() !== se
  ) {
    malformed("invalid timestamp");
  }
  return t.getTime();
}

function checkDigest(v: unknown, what: string): void {
  if (typeof v !== "string" || !DIGEST_RE.test(v)) {
    malformed(`${what} must be sha256:<64 hex>`);
  }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    return false;
  }
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

// PRV-020/021/022: self-asserted default, digests only, never raw prompts.
// Absent (null/undefined) omits the key; otherwise returns a copy.
function normalizeGenerator(gen: unknown): Record<string, unknown> | null {
  if (gen === null || gen === undefined) {
    return null;
  }
  if (!isPlainObject(gen)) {
    malformed("generator must be an object");
  }
  for (const raw of RAW_PROMPT_KEYS) {
    if (raw in gen) {
      malformed(`generator must not embed raw ${JSON.stringify(raw)} (digests only)`);
    }
  }
  const kind = gen["kind"];
  if (typeof kind !== "string" || !GENERATOR_KINDS.has(kind)) {
    malformed("generator.kind must be ai|human|tool|mixed");
  }
  const out: Record<string, unknown> = { ...gen };
  if (out["assurance"] === null || out["assurance"] === undefined) {
    out["assurance"] = "self_asserted"; // PRV-021 default claim
  }
  if (typeof out["assurance"] !== "string" || !ASSURANCES.has(out["assurance"] as string)) {
    malformed("generator.assurance unknown");
  }
  for (const f of ["prompt_digest", "toolcalls_digest"] as const) {
    if (f in out && out[f] !== null && out[f] !== undefined) {
      checkDigest(out[f], `generator.${f}`);
    }
  }
  if ("human_approver" in out && out["human_approver"] !== null && out["human_approver"] !== undefined) {
    if (typeof out["human_approver"] !== "string" || !AGENT_RE.test(out["human_approver"] as string)) {
      malformed("generator.human_approver malformed");
    }
  }
  for (const f of ["model", "runtime"] as const) {
    if (f in out && out[f] !== null && out[f] !== undefined && !isPlainObject(out[f])) {
      malformed(`generator.${f} must be an object`);
    }
  }
  return out;
}

function checkAnnotations(operation: string, ann: unknown): void {
  if (ann === null || ann === undefined) {
    if (operation === "verify") {
      malformed("verify node needs annotations.verification");
    }
    return;
  }
  if (!isPlainObject(ann)) {
    malformed("annotations must be an object");
  }
  if (operation === "verify") {
    // PRV-012
    const ver = (ann as Record<string, unknown>)["verification"];
    if (!isPlainObject(ver)) {
      malformed("verify node needs annotations.verification");
    }
    if (ver["outcome"] !== "pass" && ver["outcome"] !== "fail") {
      malformed("verification.outcome must be pass|fail");
    }
    if (typeof ver["scope"] !== "string") {
      malformed("verification.scope must be a string");
    }
  }
}

function checkParents(parents: unknown): string[] {
  if (!Array.isArray(parents)) {
    malformed("parents must be a list");
  }
  for (const p of parents as unknown[]) {
    checkDigest(p, "parent");
  }
  const list = parents as string[];
  if (new Set(list).size !== list.length) {
    malformed("parents must not contain duplicates"); // PRV-001
  }
  const sorted = [...list].sort();
  for (let i = 0; i < list.length; i++) {
    if (list[i] !== sorted[i]) {
      malformed("parents must be sorted ascending"); // PRV-001
    }
  }
  return [...list];
}

function checkArity(operation: string, parents: string[]): void {
  const n = parents.length;
  if (operation === "create") {
    if (n !== 0) {
      throw err("ERR_INVALID_PARENT", "create requires 0 parents");
    }
  } else if (operation === "merge") {
    if (n < 2) {
      throw err("ERR_INVALID_PARENT", "merge requires >= 2 parents");
    }
  } else if (
    operation === "modify" || operation === "revert" ||
    operation === "supersede" || operation === "verify"
  ) {
    if (n < 1) {
      throw err("ERR_INVALID_PARENT", `${operation} requires >= 1 parent`);
    }
  } else {
    malformed("unknown operation");
  }
}

function buildNode(
  contentRoot: unknown,
  parents: unknown,
  operation: unknown,
  actor: unknown,
  taskId: unknown,
  generator: unknown,
  now: unknown,
  annotations: unknown = null,
): ProvenanceNode {
  checkDigest(contentRoot, "content_root");
  const cleanParents = checkParents(parents);
  if (typeof operation !== "string" || !OPERATIONS.has(operation)) {
    malformed("unknown operation");
  }
  checkArity(operation as string, cleanParents);
  if (typeof actor !== "string" || !AGENT_RE.test(actor)) {
    malformed("actor malformed");
  }
  if (typeof taskId !== "string" || !TASK_RE.test(taskId)) {
    malformed("task_id malformed");
  }
  parseTs(now);
  const gen = normalizeGenerator(generator);
  checkAnnotations(operation as string, annotations);
  const node: ProvenanceNode = {
    v: "0.2",
    content_root: contentRoot as string,
    parents: cleanParents,
    operation: operation as string,
    actor: actor as string,
    task_id: taskId as string,
    created_at: now as string,
  };
  if (gen !== null) {
    node.generator = gen;
  }
  if (annotations !== null && annotations !== undefined) {
    node.annotations = annotations as Record<string, unknown>;
  }
  return node;
}

export function nodeIdOf(node: ProvenanceNode): string {
  const body = jcs(node);
  const pre = new Uint8Array(D_NODE.length + body.length);
  pre.set(D_NODE, 0);
  pre.set(body, D_NODE.length);
  return "sha256:" + hex(sha256(pre));
}

export function makeNode(
  contentRoot: string,
  parents: string[],
  operation: string,
  actor: string,
  taskId: string,
  generator: GeneratorInput,
  now: string,
  annotations: AnnotationsInput = null,
): { node: ProvenanceNode; nodeId: string } {
  // Create a node dict and its node_id (PRV-001/006, GEN-004).
  const node = buildNode(
    contentRoot,
    parents,
    operation,
    actor,
    taskId,
    generator,
    now,
    annotations,
  );
  return { node, nodeId: nodeIdOf(node) };
}

export function makeNodeEnvelope(
  node: ProvenanceNode,
  signer: EnvelopeSigner,
): DsseEnvelope {
  // Publish a node as a DSSE node+json envelope signed by actor (PRV-002).
  return makeEnvelope(PT_NODE, jcs(node), signer);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

export function validateNode(node: unknown): string {
  // Validate shape/arity/timestamps; return the recomputed node_id.
  if (!isPlainObject(node)) {
    malformed("node must be an object");
  }
  const rec = node as Record<string, unknown>;
  if (rec["v"] !== "0.2") {
    throw err("ERR_PROTOCOL_VERSION", "node v must be 0.2");
  }
  for (const f of ["content_root", "parents", "operation", "actor", "task_id", "created_at"]) {
    if (!(f in rec)) {
      malformed(`node missing ${f}`);
    }
  }
  const rebuilt = buildNode(
    rec["content_root"],
    rec["parents"],
    rec["operation"],
    rec["actor"],
    rec["task_id"],
    rec["generator"] ?? null,
    rec["created_at"],
    rec["annotations"] ?? null,
  );
  if (!bytesEqual(jcs(rebuilt), jcs(rec))) {
    malformed("node not in canonical form");
  }
  return nodeIdOf(rebuilt);
}

interface StoredNode {
  node: ProvenanceNode;
  envelope: DsseEnvelope;
}

export class DagStore {
  // In-memory provenance DAG with lazy/require parent policy (PRV-010/011).
  // Fields use `private` (not #) so tests can inject synthetic graphs the
  // way Python tests write store._nodes directly.
  private policy: "lazy" | "require";
  private skew: number;
  private nodes: Map<string, StoredNode>;

  constructor(
    parentPolicy: string = "lazy",
    clockSkewSeconds: number = CLOCK_SKEW_SECONDS,
  ) {
    if (parentPolicy !== "lazy" && parentPolicy !== "require") {
      malformed("parent_policy must be lazy|require");
    }
    this.policy = parentPolicy;
    this.skew = clockSkewSeconds;
    this.nodes = new Map();
  }

  private ensureNoCycle(nodeId: string, parents: string[]): void {
    // PRV-003: reject if nodeId appears among its own ancestors.
    if (parents.includes(nodeId)) {
      throw err("ERR_DAG_CYCLE", "node lists itself as parent");
    }
    const seen = new Set<string>();
    const stack = [...parents];
    while (stack.length > 0) {
      const cur = stack.pop() as string;
      if (cur === nodeId) {
        throw err("ERR_DAG_CYCLE", "node among its own ancestors");
      }
      if (seen.has(cur)) {
        continue;
      }
      seen.add(cur);
      const entry = this.nodes.get(cur);
      if (entry !== undefined) {
        stack.push(...entry.node.parents);
      }
      if (seen.size > 100000) {
        throw err("ERR_DAG_CYCLE", "ancestry too deep / cycle suspected");
      }
    }
  }

  private transitive(nodeId: string): { ancestors: string[]; complete: boolean } {
    // Return ancestors plus whether every parent resolves (PRV-011).
    const root = this.nodes.get(nodeId);
    if (root === undefined) {
      throw err("ERR_ARTIFACT_NOT_FOUND", "unknown node");
    }
    const out: string[] = [];
    const seen = new Set<string>();
    const path = new Set<string>([nodeId]);
    let complete = true;
    const self = this;
    function visit(cur: string): void {
      const entry = self.nodes.get(cur);
      if (entry === undefined) {
        complete = false;
        return;
      }
      for (const p of entry.node.parents) {
        if (path.has(p)) {
          throw err("ERR_DAG_CYCLE", "cycle in stored ancestry");
        }
        if (!seen.has(p)) {
          seen.add(p);
          out.push(p);
          if (!self.nodes.has(p)) {
            complete = false;
          } else {
            path.add(p);
            visit(p);
            path.delete(p);
          }
        }
      }
    }
    try {
      visit(nodeId);
      path.delete(nodeId);
    } catch (e) {
      if (e instanceof RangeError) {
        throw err("ERR_INVALID_PARENT", "ancestry too deep");
      }
      throw e;
    }
    return { ancestors: out, complete };
  }

  add(envelope: unknown, keyResolver: KeyResolver): string {
    // Verify envelope (PRV-002), validate node, enforce time/cycle/policy.
    if (!isPlainObject(envelope) || typeof envelope["payload"] !== "string") {
      malformed("node envelope must carry a string payload");
    }
    let raw: Uint8Array;
    try {
      raw = b64uDec(envelope["payload"] as string);
    } catch (e) {
      if (e instanceof AATPError) {
        malformed("node payload not valid base64url");
      }
      throw e;
    }
    let peek: unknown;
    try {
      peek = parseJcs(raw);
    } catch {
      malformed("node payload not canonical JSON");
    }
    if (!isPlainObject(peek)) {
      malformed("node payload must be a JSON object");
    }
    const actor = (peek as Record<string, unknown>)["actor"];
    if (typeof actor !== "string" || !AGENT_RE.test(actor)) {
      malformed("node actor malformed");
    }
    let pubkey: Uint8Array;
    try {
      pubkey = keyResolver(actor);
    } catch (e) {
      if (e instanceof AATPError) {
        throw e;
      }
      throw err("ERR_AUTH_FAILED", "key resolution failed");
    }
    if (!(pubkey instanceof Uint8Array) || pubkey.length !== 32) {
      throw err("ERR_AUTH_FAILED", "resolved key must be 32 bytes");
    }
    const node = verifyEnvelope(envelope, PT_NODE, pubkey);
    if (!isPlainObject(node)) {
      malformed("node payload must be a JSON object");
    }
    const nodeId = validateNode(node);
    if (this.nodes.has(nodeId)) {
      return nodeId; // idempotent replay
    }
    const typed = node as unknown as ProvenanceNode;
    const childTs = parseTs(typed.created_at);
    const unknown: string[] = [];
    for (const p of typed.parents) {
      const parent = this.nodes.get(p);
      if (parent === undefined) {
        unknown.push(p);
        continue;
      }
      const parentTs = parseTs(parent.node.created_at);
      if ((childTs - parentTs) / 1000 < -this.skew) {
        // PRV-005
        throw err("ERR_INVALID_PARENT", "created_at older than parent");
      }
    }
    if (unknown.length > 0 && this.policy === "require") {
      // PRV-010
      throw err("ERR_INVALID_PARENT", "unresolvable parent");
    }
    this.ensureNoCycle(nodeId, typed.parents); // PRV-003
    this.nodes.set(nodeId, {
      node: typed,
      envelope: envelope as unknown as DsseEnvelope,
    });
    return nodeId;
  }

  get(nodeId: string): ProvenanceNode {
    const entry = this.nodes.get(nodeId);
    if (entry === undefined) {
      throw err("ERR_ARTIFACT_NOT_FOUND", "unknown node");
    }
    return { ...entry.node };
  }

  ancestors(nodeId: string): string[] {
    const { ancestors } = this.transitive(nodeId);
    this.ensureNoCycle(nodeId, ancestors);
    return ancestors;
  }

  ancestryStatus(nodeId: string): string {
    const { complete } = this.transitive(nodeId);
    return complete ? "complete" : "partial"; // PRV-011
  }
}
