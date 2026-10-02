import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { sha256 } from "@noble/hashes/sha2.js";
import { jcs } from "../src/canon.ts";
import { hex } from "../src/b64.ts";
import { PT_NODE, verifyEnvelope } from "../src/dsse.ts";
import { deriveAgentId } from "../src/ids.ts";
import { SoftwareSigner } from "../src/signer.ts";
import {
  DagStore,
  D_NODE,
  makeNode,
  makeNodeEnvelope,
  nodeIdOf,
  validateNode,
} from "../src/node.ts";

const CR1 = "sha256:9067a66c672c42accf461d38069a837189e8e2fe0713f4edc6f8e5ec3ce9c1cf";
const CR2 = "sha256:316dcfe880067987f2d83df8c040db75612d521f7df41ffe37a1847bed253bec";
const SEED = new Uint8Array(32).fill(0x77);
const WRONG_SEED = new Uint8Array(32).fill(0x88);
const TASK = "task_local_m3_001";
const T0 = "2026-10-01T00:00:00Z";
const T1 = "2026-10-01T00:01:00Z";
const T2 = "2026-10-01T00:02:00Z";

function signer(seed: Uint8Array = SEED): SoftwareSigner {
  return SoftwareSigner.fromSeed(seed, "n0");
}

function actor(seed: Uint8Array = SEED): string {
  return deriveAgentId(signer(seed).publicKeyRaw());
}

function resolver(
  signers: Record<string, SoftwareSigner>,
): (a: string) => Uint8Array {
  const pubs: Record<string, Uint8Array> = {};
  for (const [a, s] of Object.entries(signers)) {
    pubs[a] = s.publicKeyRaw();
  }
  return (a: string) => {
    const p = pubs[a];
    if (!p) {
      throw Object.assign(new Error("unknown actor"), {
        code: "ERR_AUTH_FAILED",
        numeric: 1102,
      });
    }
    return p;
  };
}

function codeOf(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    return (e as { code: string }).code;
  }
  assert.fail("expected throw");
}

describe("PRV-001 node identity", () => {
  it("D_NODE is byte-exact ASCII", () => {
    assert.equal(
      Buffer.from(D_NODE).toString(),
      "AATP/0.2/NODE\n",
    );
  });
  it("deterministic: same inputs give same id", () => {
    const a = actor();
    const { node: n1, nodeId: id1 } = makeNode(CR1, [], "create", a, TASK, null, T0);
    const { node: n2, nodeId: id2 } = makeNode(CR1, [], "create", a, TASK, null, T0);
    assert.deepEqual(n1, n2);
    assert.equal(id1, id2);
  });
  it("node_id recomputes independently as sha256 hex of D_NODE + JCS", () => {
    const a = actor();
    const { node, nodeId } = makeNode(CR1, [], "create", a, TASK, null, T0);
    const pre = new Uint8Array([...D_NODE, ...jcs(node)]);
    assert.equal(nodeId, "sha256:" + hex(sha256(pre)));
    assert.equal(nodeIdOf(node), nodeId);
  });
  it("unsorted parents rejected", () => {
    const a = actor();
    const { nodeId: idA } = makeNode(CR1, [], "create", a, TASK, null, T0);
    const { nodeId: idB } = makeNode(CR1, [], "create", a, TASK, null, T1);
    const [lo, hi] = [idA, idB].sort();
    assert.equal(
      codeOf(() => makeNode(CR1, [hi, lo], "merge", a, TASK, null, T2)),
      "ERR_MALFORMED_MESSAGE",
    );
  });
  it("duplicate parents rejected", () => {
    const a = actor();
    const { nodeId: idA } = makeNode(CR1, [], "create", a, TASK, null, T0);
    assert.equal(
      codeOf(() => makeNode(CR1, [idA, idA], "merge", a, TASK, null, T1)),
      "ERR_MALFORMED_MESSAGE",
    );
  });
  it("malformed digests rejected", () => {
    const a = actor();
    assert.equal(
      codeOf(() => makeNode("nope", [], "create", a, TASK, null, T0)),
      "ERR_MALFORMED_MESSAGE",
    );
    assert.equal(
      codeOf(() => makeNode(CR1, ["sha256:" + "zz".repeat(32)], "modify", a, TASK, null, T0)),
      "ERR_MALFORMED_MESSAGE",
    );
  });
});

describe("PRV-006 arity (ERR_INVALID_PARENT)", () => {
  it("create=0, merge>=2, others>=1", () => {
    const a = actor();
    const fake = "sha256:" + "0".repeat(64);
    assert.equal(codeOf(() => makeNode(CR1, [fake], "create", a, TASK, null, T0)), "ERR_INVALID_PARENT");
    assert.equal(codeOf(() => makeNode(CR1, [fake], "merge", a, TASK, null, T0)), "ERR_INVALID_PARENT");
    for (const op of ["modify", "revert", "supersede", "verify"] as const) {
      const ann = op === "verify"
        ? { verification: { outcome: "pass", scope: "s" } }
        : undefined;
      assert.equal(codeOf(() => makeNode(CR1, [], op, a, TASK, null, T0, ann)), "ERR_INVALID_PARENT", op);
    }
    assert.equal(codeOf(() => makeNode(CR1, [], "bogus", a, TASK, null, T0)), "ERR_MALFORMED_MESSAGE");
  });
});

describe("PRV-004 revert accepted, distinct id", () => {
  it("same contentRoot with different parents gives different ids, all accepted", () => {
    const a = actor();
    const s = signer();
    const res = resolver({ [a]: s });
    const { node: n1 } = makeNode(CR1, [], "create", a, TASK, null, T0);
    const { node: n2, nodeId: id2 } = makeNode(CR2, [nodeIdOf(n1)], "modify", a, TASK, null, T1);
    const { node: n3, nodeId: id3 } = makeNode(CR1, [id2], "revert", a, TASK, null, T2);
    assert.notEqual(id3, nodeIdOf(n1));
    const store = new DagStore();
    for (const n of [n1, n2, n3]) {
      store.add(makeNodeEnvelope(n, s), res);
    }
    assert.equal(store.get(id3).content_root, CR1);
    assert.equal(store.ancestryStatus(id3), "complete");
  });
});

describe("PRV-003 cycle (synthetic graph)", () => {
  it("A<->B ancestry reports ERR_DAG_CYCLE and direct self-parent is rejected", () => {
    const a = actor();
    const store = new DagStore();
    const inner = store as unknown as {
      nodes: Map<string, { node: Record<string, unknown>; envelope: unknown }>;
      ensureNoCycle(id: string, parents: string[]): void;
    };
    const mkNode = (parents: string[]): Record<string, unknown> => ({
      v: "0.2",
      content_root: CR1,
      parents,
      operation: "modify",
      actor: a,
      task_id: TASK,
      created_at: T1,
    });
    inner.nodes.set("sha256:" + "a".repeat(64), {
      node: mkNode(["sha256:" + "b".repeat(64)]),
      envelope: {},
    });
    inner.nodes.set("sha256:" + "b".repeat(64), {
      node: mkNode(["sha256:" + "a".repeat(64)]),
      envelope: {},
    });
    assert.equal(
      codeOf(() => store.ancestors("sha256:" + "a".repeat(64))),
      "ERR_DAG_CYCLE",
    );
    assert.equal(
      codeOf(() => inner.ensureNoCycle("sha256:" + "c".repeat(64), ["sha256:" + "c".repeat(64)])),
      "ERR_DAG_CYCLE",
    );
  });
});

describe("PRV-005 skew boundary 120/121", () => {
  it("child 121s older than parent rejected, exactly 120s accepted", () => {
    const a = actor();
    const s = signer();
    const res = resolver({ [a]: s });
    const store = new DagStore();
    const { node: n1, nodeId: id1 } = makeNode(CR1, [], "create", a, TASK, null, "2026-10-01T01:00:00Z");
    store.add(makeNodeEnvelope(n1, s), res);
    const { node: nOld } = makeNode(CR2, [id1], "modify", a, TASK, null, "2026-10-01T00:57:59Z");
    assert.equal(codeOf(() => store.add(makeNodeEnvelope(nOld, s), res)), "ERR_INVALID_PARENT");
    const { node: nEdge, nodeId: idEdge } = makeNode(CR2, [id1], "modify", a, TASK, null, "2026-10-01T00:58:00Z");
    assert.equal(store.add(makeNodeEnvelope(nEdge, s), res), idEdge);
  });
});

describe("PRV-002 signed by actor", () => {
  it("correct key verifies; wrong key fails signature", () => {
    const a = actor();
    const good = signer();
    const bad = SoftwareSigner.fromSeed(WRONG_SEED, "n0");
    const { node: n1 } = makeNode(CR1, [], "create", a, TASK, null, T0);
    const store = new DagStore();
    const res = resolver({ [a]: good });
    const env = makeNodeEnvelope(n1, good);
    assert.equal((env as { payloadType: string }).payloadType, PT_NODE);
    assert.deepEqual(verifyEnvelope(env, PT_NODE, good.publicKeyRaw()), n1);
    assert.equal(codeOf(() => store.add(makeNodeEnvelope(n1, bad), res)), "ERR_SIGNATURE_INVALID");
  });
  it("replay of the same envelope is idempotent", () => {
    const a = actor();
    const s = signer();
    const res = resolver({ [a]: s });
    const store = new DagStore();
    const { node: n1, nodeId: id1 } = makeNode(CR1, [], "create", a, TASK, null, T0);
    const env = makeNodeEnvelope(n1, s);
    assert.equal(store.add(env, res), id1);
    assert.equal(store.add(env, res), id1);
  });
});

describe("PRV-010/011 parent policy", () => {
  it("require rejects unknown parents", () => {
    const a = actor();
    const s = signer();
    const res = resolver({ [a]: s });
    const store = new DagStore("require");
    const ghost = "sha256:" + "f".repeat(64);
    const { node } = makeNode(CR1, [ghost], "modify", a, TASK, null, T0);
    assert.equal(codeOf(() => store.add(makeNodeEnvelope(node, s), res)), "ERR_INVALID_PARENT");
  });
  it("lazy accepts unknown parents and reports partial", () => {
    const a = actor();
    const s = signer();
    const res = resolver({ [a]: s });
    const store = new DagStore();
    const { node: n1, nodeId: id1 } = makeNode(CR1, [], "create", a, TASK, null, T0);
    store.add(makeNodeEnvelope(n1, s), res);
    assert.equal(store.ancestryStatus(id1), "complete");
    assert.deepEqual(store.ancestors(id1), []);
    const ghost = "sha256:" + "e".repeat(64);
    const parents = [id1, ghost].sort();
    const { node: n2, nodeId: id2 } = makeNode(CR2, parents, "merge", a, TASK, null, T1);
    assert.deepEqual(n2.parents, parents);
    store.add(makeNodeEnvelope(n2, s), res);
    assert.equal(store.ancestryStatus(id2), "partial");
    assert.ok(store.ancestors(id2).includes(id1));
  });
  it("unknown node status/get fail artifact-not-found", () => {
    const store = new DagStore();
    const ghost = "sha256:" + "f".repeat(64);
    assert.equal(codeOf(() => store.ancestryStatus(ghost)), "ERR_ARTIFACT_NOT_FOUND");
    assert.equal(codeOf(() => store.get(ghost)), "ERR_ARTIFACT_NOT_FOUND");
  });
});

describe("PRV-012 verify operation annotations", () => {
  it("verify needs verification{outcome pass|fail, scope str}", () => {
    const a = actor();
    const s = signer();
    const res = resolver({ [a]: s });
    const store = new DagStore();
    const { node: n1, nodeId: id1 } = makeNode(CR1, [], "create", a, TASK, null, T0);
    store.add(makeNodeEnvelope(n1, s), res);
    assert.equal(codeOf(() => makeNode(CR2, [id1], "verify", a, TASK, null, T1)), "ERR_MALFORMED_MESSAGE");
    assert.equal(
      codeOf(() => makeNode(CR2, [id1], "verify", a, TASK, null, T1, { verification: { outcome: "maybe", scope: "s" } })),
      "ERR_MALFORMED_MESSAGE",
    );
    assert.equal(
      codeOf(() => makeNode(CR2, [id1], "verify", a, TASK, null, T1, { verification: { outcome: "pass", scope: 7 } })),
      "ERR_MALFORMED_MESSAGE",
    );
    const { node, nodeId } = makeNode(
      CR2,
      [id1],
      "verify",
      a,
      TASK,
      null,
      T1,
      { verification: { outcome: "pass", scope: "manual review" } },
    );
    assert.equal(store.add(makeNodeEnvelope(node, s), res), nodeId);
  });
});

describe("PRV-020/021/022 generator", () => {
  it("absent generator omits the key", () => {
    const a = actor();
    const { node } = makeNode(CR1, [], "create", a, TASK, null, T0);
    assert.ok(!("generator" in node));
  });
  it("missing assurance defaults to self_asserted", () => {
    const a = actor();
    const { node } = makeNode(CR1, [], "create", a, TASK, { kind: "ai" }, T0);
    assert.deepEqual(node.generator, { kind: "ai", assurance: "self_asserted" });
  });
  it("rejects raw prompt keys, bad kinds, bad digests", () => {
    const a = actor();
    assert.equal(codeOf(() => makeNode(CR1, [], "create", a, TASK, { kind: "ai", prompt: "x" }, T0)), "ERR_MALFORMED_MESSAGE");
    assert.equal(codeOf(() => makeNode(CR1, [], "create", a, TASK, { kind: "ai", prompt_text: "x" }, T0)), "ERR_MALFORMED_MESSAGE");
    assert.equal(codeOf(() => makeNode(CR1, [], "create", a, TASK, { kind: "ai", toolcalls: [] }, T0)), "ERR_MALFORMED_MESSAGE");
    assert.equal(codeOf(() => makeNode(CR1, [], "create", a, TASK, { kind: "robot" }, T0)), "ERR_MALFORMED_MESSAGE");
    assert.equal(codeOf(() => makeNode(CR1, [], "create", a, TASK, { kind: "ai", prompt_digest: "nope" }, T0)), "ERR_MALFORMED_MESSAGE");
    assert.equal(codeOf(() => makeNode(CR1, [], "create", a, TASK, "not-an-object" as never, T0)), "ERR_MALFORMED_MESSAGE");
  });
  it("digests must be sha256 shaped when present", () => {
    const a = actor();
    const { node } = makeNode(
      CR1,
      [],
      "create",
      a,
      TASK,
      { kind: "tool", prompt_digest: "sha256:" + "0".repeat(64) },
      T0,
    );
    assert.equal(
      (node.generator as Record<string, unknown>)["prompt_digest"],
      "sha256:" + "0".repeat(64),
    );
  });
});

describe("GEN-004 strict timestamps + shape", () => {
  it("rejects bad formats and impossible dates", () => {
    const a = actor();
    for (const bad of ["2026-10-01", "2026-13-01T00:00:00Z", "2026-02-30T00:00:00Z", "2026-10-01T25:00:00Z", "2026-10-01T00:00:00+00:00", "2026-10-01T00:00:00.000Z"]) {
      assert.equal(codeOf(() => makeNode(CR1, [], "create", a, TASK, null, bad)), "ERR_MALFORMED_MESSAGE", bad);
    }
  });
  it("rejects malformed actor, task_id, operation", () => {
    const a = actor();
    assert.equal(codeOf(() => makeNode(CR1, [], "create", "not-an-agent", TASK, null, T0)), "ERR_MALFORMED_MESSAGE");
    assert.equal(codeOf(() => makeNode(CR1, [], "create", a, "", null, T0)), "ERR_MALFORMED_MESSAGE");
    assert.equal(codeOf(() => makeNode(CR1, [], "create", a, "has space", null, T0)), "ERR_MALFORMED_MESSAGE");
  });
  it("validateNode returns the id and enforces canonical form", () => {
    const a = actor();
    const { node, nodeId } = makeNode(CR1, [], "create", a, TASK, null, T0);
    assert.equal(validateNode(node), nodeId);
    assert.equal(codeOf(() => validateNode({ ...node, v: "0.3" })), "ERR_PROTOCOL_VERSION");
    assert.equal(codeOf(() => validateNode({ ...node, extra: 1 })), "ERR_MALFORMED_MESSAGE");
    assert.equal(codeOf(() => validateNode([1, 2] as never)), "ERR_MALFORMED_MESSAGE");
  });
});
