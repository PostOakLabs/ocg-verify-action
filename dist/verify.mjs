#!/usr/bin/env node
// ocg-verify-action — dist/verify.mjs
//
// Ported, byte-for-byte where the math is concerned, from the browser-verified
// implementation in ainumbers/tools/568-ocg-receipt-verifier.html (lines
// ~276-528: OCG-CORE v1 canon/hash, RFC 6962 Merkle inclusion, checkpoint-note
// parser, verifyReceipt). Only the I/O layer is new (file walk instead of
// paste/upload, job-summary instead of DOM). Per CI-VERIFY-BUILD-SPEC.md §A1:
// "Do NOT re-derive the hash/proof math from spec text — copy the browser
// tool's verified implementation byte-for-byte then adapt only the I/O layer."
//
// Zero npm dependencies (§A2). Node's built-in crypto.webcrypto only.

import { webcrypto } from 'node:crypto';
import { readFileSync, readdirSync, statSync, appendFileSync } from 'node:fs';
import { join, relative } from 'node:path';

const crypto = webcrypto;

/* ══════════════════════════════════════════════════════════════
   OCG-CORE v1 — canon / execution_hash (OCG Standard §4).
   Ported verbatim from tools/568-ocg-receipt-verifier.html.
══════════════════════════════════════════════════════════════ */
function assertIJson(v) {
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new Error('Non-finite number is not valid I-JSON.');
    if (Number.isInteger(v) && !Number.isSafeInteger(v)) throw new Error('Integer exceeds 2^53.');
  } else if (Array.isArray(v)) {
    v.forEach(assertIJson);
  } else if (v && typeof v === 'object') {
    for (const k in v) if (Object.prototype.hasOwnProperty.call(v, k)) assertIJson(v[k]);
  }
}
function cgCanon(v) {
  if (Array.isArray(v)) return v.map(cgCanon);
  if (v && typeof v === 'object') {
    const keys = Object.keys(v).sort();
    const o = {};
    for (const k of keys) o[k] = cgCanon(v[k]);
    return o;
  }
  return v;
}
function canonicalPreimage(policy_parameters, output_payload) {
  const obj = { policy_parameters, output_payload };
  assertIJson(obj);
  return JSON.stringify(cgCanon(obj));
}
async function executionHash(policy_parameters, output_payload) {
  const bytes = new TextEncoder().encode(canonicalPreimage(policy_parameters, output_payload));
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('');
}
function jcsBytes(obj) { return new TextEncoder().encode(JSON.stringify(cgCanon(obj))); }
async function sha256(bytes) { const d = await crypto.subtle.digest('SHA-256', bytes); return new Uint8Array(d); }
function hexToBytes(hex) {
  hex = String(hex || '');
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.substr(i * 2, 2), 16);
  return b;
}
function bytesToHex(b) { return Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join(''); }

/* ── base58btc, did:key, eddsa-jcs-2022 verify (OCG Standard §16) ── */
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58decode(str) {
  let zeros = 0; while (zeros < str.length && str[zeros] === '1') zeros++;
  const bytes = [0];
  for (let i = zeros; i < str.length; i++) {
    let carry = B58.indexOf(str[i]); if (carry < 0) throw new Error('bad base58 char');
    for (let j = 0; j < bytes.length; j++) { carry += bytes[j] * 58; bytes[j] = carry & 0xff; carry >>= 8; }
    while (carry) { bytes.push(carry & 0xff); carry >>= 8; }
  }
  const out = new Uint8Array(zeros + bytes.length);
  for (let k = 0; k < bytes.length; k++) out[zeros + bytes.length - 1 - k] = bytes[k];
  return out;
}
async function didKeyToPublicKey(did) {
  if (!did || did.indexOf('did:key:z') !== 0) throw new Error('not a did:key z-form');
  const prefixed = b58decode(did.slice('did:key:z'.length));
  if (prefixed[0] !== 0xed || prefixed[1] !== 0x01) throw new Error('did:key is not Ed25519');
  const raw = prefixed.slice(2);
  return crypto.subtle.importKey('raw', raw, { name: 'Ed25519' }, true, ['verify']);
}
function proofOptions(o) {
  return { type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', verificationMethod: o.verificationMethod, proofPurpose: 'assertionMethod', created: o.created };
}
async function hashData(doc, opts) {
  const optHash = await sha256(jcsBytes(opts));
  const docHash = await sha256(jcsBytes(doc));
  const cat = new Uint8Array(optHash.length + docHash.length);
  cat.set(optHash, 0); cat.set(docHash, optHash.length);
  return cat;
}
// §16 home: audit_signature.proof (object OR array of proof-set members) — NOT root-level `proof`.
function securedArtifact(a) {
  const c = JSON.parse(JSON.stringify(a));
  if (c && c.audit_signature && ('proof' in c.audit_signature)) delete c.audit_signature.proof;
  return c;
}
async function verifyOneProof(secured, proof) {
  if (!proof || proof.type !== 'DataIntegrityProof' || proof.cryptosuite !== 'eddsa-jcs-2022')
    return { valid: false, verificationMethod: proof && proof.verificationMethod, error: 'unsupported proof type/cryptosuite — only eddsa-jcs-2022 is verified' };
  if (proof.proofPurpose !== 'assertionMethod' || typeof proof.proofValue !== 'string' || proof.proofValue[0] !== 'z')
    return { valid: false, verificationMethod: proof.verificationMethod, error: 'malformed proof object' };
  try {
    const pub = await didKeyToPublicKey(proof.verificationMethod);
    const opts = proofOptions(proof);
    const sig = b58decode(proof.proofValue.slice(1));
    const ok = await crypto.subtle.verify('Ed25519', pub, sig, await hashData(secured, opts));
    return { valid: ok, verificationMethod: proof.verificationMethod, error: ok ? null : 'signature does not verify against the named key' };
  } catch (e) { return { valid: false, verificationMethod: proof.verificationMethod, error: e.message }; }
}
async function verifyArtifactProofs(artifact) {
  const raw = artifact && artifact.audit_signature && artifact.audit_signature.proof;
  const proofs = raw == null ? [] : (Array.isArray(raw) ? raw : [raw]);
  if (proofs.length === 0) return { present: false, allValid: true, results: [] };
  const secured = securedArtifact(artifact);
  const results = [];
  for (let i = 0; i < proofs.length; i++) results.push(await verifyOneProof(secured, proofs[i]));
  const allValid = results.every((r) => r.valid);
  return { present: true, allValid, results };
}

/* ══════════════════════════════════════════════════════════════
   RFC 6962 / RFC 9162 Merkle inclusion (OCG Standard §20.1).
   Ported verbatim from tools/568-ocg-receipt-verifier.html.
══════════════════════════════════════════════════════════════ */
function concatBytes(a, b) { const out = new Uint8Array(a.length + b.length); out.set(a, 0); out.set(b, a.length); return out; }
async function leafHash(data) { return sha256(concatBytes(new Uint8Array([0x00]), data)); }
async function nodeHash(l, r) { return sha256(concatBytes(new Uint8Array([0x01]), concatBytes(l, r))); }
async function rootFromInclusion(leaf, index, size, path) {
  if (index >= size) return null;
  let fn = BigInt(index), sn = BigInt(size) - 1n;
  let r = leaf;
  for (let i = 0; i < path.length; i++) {
    const v = path[i];
    if (sn === 0n) return null;
    if ((fn & 1n) === 1n || fn === sn) {
      r = await nodeHash(v, r);
      if ((fn & 1n) === 0n) { while (fn !== 0n && (fn & 1n) === 0n) { fn >>= 1n; sn >>= 1n; } }
    } else {
      r = await nodeHash(r, v);
    }
    fn >>= 1n; sn >>= 1n;
  }
  return sn === 0n ? r : null;
}
async function verifyMerkleInclusion(mi, execHashHex) {
  if (!mi || typeof mi !== 'object') return { ok: false, reason: 'merkle_inclusion must be an object' };
  if (mi.algorithm !== 'rfc6962') return { ok: false, reason: 'merkle_inclusion.algorithm must be "rfc6962"' };
  const leafHex = String(mi.leaf || '').replace(/^sha256:/, '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(leafHex)) return { ok: false, reason: 'merkle_inclusion.leaf must be a 64-hex digest' };
  if (leafHex !== String(execHashHex || '').toLowerCase()) return { ok: false, reason: 'merkle_inclusion.leaf != recomputed execution_hash' };
  if (!Number.isInteger(mi.index) || mi.index < 0) return { ok: false, reason: 'merkle_inclusion.index must be a non-negative integer' };
  if (!Number.isInteger(mi.tree_size) || mi.tree_size <= 0) return { ok: false, reason: 'merkle_inclusion.tree_size must be a positive integer' };
  if (!Array.isArray(mi.path)) return { ok: false, reason: 'merkle_inclusion.path must be an array' };
  try {
    const L = await leafHash(hexToBytes(leafHex));
    const pathBytes = mi.path.map((h) => hexToBytes(String(h).replace(/^sha256:/, '')));
    const root = await rootFromInclusion(L, mi.index, mi.tree_size, pathBytes);
    if (!root) return { ok: false, reason: 'inclusion path does not reconstruct a root (index/size/path inconsistent)' };
    return { ok: true, rootHex: bytesToHex(root) };
  } catch (e) { return { ok: false, reason: 'inclusion path malformed: ' + e.message }; }
}

/* ══════════════════════════════════════════════════════════════
   Checkpoint-note parser — ported from tools/568 (adapted from
   WITNESS-VERIFY-1's parseNote). Used only for snapshot-batch mode.
══════════════════════════════════════════════════════════════ */
function b64ToBytes(s) {
  const bin = Buffer.from(String(s || '').trim(), 'base64');
  return new Uint8Array(bin);
}
function parseCheckpointNote(text) {
  const raw = String(text || '');
  const sep = raw.indexOf('\n\n');
  const header = sep >= 0 ? raw.slice(0, sep) : raw.replace(/\n$/, '');
  const headerLines = header.split('\n').filter((l) => l.length > 0);
  if (headerLines.length < 3) return { error: 'checkpoint note needs origin, size, and root lines' };
  const origin = headerLines[0], sizeStr = headerLines[1], rootB64 = headerLines[2];
  const size = Number(sizeStr);
  if (!Number.isInteger(size) || size < 0) return { error: 'checkpoint size line is not a non-negative integer' };
  let rootBytes;
  try { rootBytes = b64ToBytes(rootB64); } catch (e) { return { error: 'checkpoint root line is not valid base64' }; }
  return { origin, size, rootHex: bytesToHex(rootBytes) };
}

/* ══════════════════════════════════════════════════════════════
   Core verifier — ported verbatim from tools/568's verifyReceipt.
   opts.trustedRootHex pins the cross-check to a checkpoint root;
   opts.requireAnchor makes an anchor_bindings entry mandatory.
══════════════════════════════════════════════════════════════ */
async function verifyReceipt(artifact, opts) {
  opts = opts || {};
  const checks = [];
  const pp = artifact && artifact.policy_parameters, op = artifact && artifact.output_payload;
  const structOk = !!(artifact && typeof artifact === 'object' && pp && typeof pp === 'object' && op && typeof op === 'object' && typeof artifact.execution_hash === 'string' && artifact.execution_hash);
  checks.push({ check: 'structure', pass: structOk, detail: structOk ? 'has policy_parameters, output_payload, execution_hash' : 'missing policy_parameters / output_payload / execution_hash (string)' });
  if (!structOk) {
    return { verdict: 'FAIL', checks, hash_match: false, recomputed_hash: null, signature: { present: false, allValid: true, results: [] }, anchors: [] };
  }

  const recomputed = await executionHash(pp, op);
  const statedHash = String(artifact.execution_hash).replace(/^sha256:/, '').toLowerCase();
  const hashMatch = recomputed.toLowerCase() === statedHash;
  checks.push({ check: 'execution_hash_recompute', pass: hashMatch, detail: hashMatch ? 'recomputed execution_hash matches the stated value' : 'recomputed execution_hash does NOT match — payload was altered after signing/anchoring' });

  const sigRes = await verifyArtifactProofs(artifact);
  if (sigRes.present) {
    checks.push({ check: 'audit_signature_proof', pass: sigRes.allValid, detail: sigRes.allValid ? (sigRes.results.length + ' eddsa-jcs-2022 signature(s) verify against ' + sigRes.results.map((r) => r.verificationMethod).join(', ')) : ('signature check failed: ' + sigRes.results.filter((r) => !r.valid).map((r) => r.error).join('; ')) });
  } else {
    checks.push({ check: 'audit_signature_proof', pass: true, detail: 'no §16 signature attached (OPTIONAL — not a failure by itself)' });
  }

  // §A6 (deliberately deferred for v1): a groth16-bn254 compute_proof is never
  // false-PASSed or false-FAILed — it's reported as a skipped check.
  const cp = artifact.audit_signature && artifact.audit_signature.compute_proof;
  if (cp && artifact.audit_signature.receiptFormat === 'groth16-bn254') {
    checks.push({ check: 'compute_proof', pass: null, detail: 'compute_proof present, not verified by this Action version' });
  }

  const anchorBindings = Array.isArray(artifact.anchor_bindings) ? artifact.anchor_bindings : [];
  const anchorResults = [];
  for (let i = 0; i < anchorBindings.length; i++) {
    const ab = anchorBindings[i];
    const anchoredHashHex = String(ab.anchored_hash || '').replace(/^sha256:/, '').toLowerCase();
    if (ab.merkle_inclusion) {
      const mres = await verifyMerkleInclusion(ab.merkle_inclusion, recomputed);
      const rootMatch = mres.ok && mres.rootHex.toLowerCase() === anchoredHashHex;
      const trustedMatch = !opts.trustedRootHex || (mres.ok && mres.rootHex.toLowerCase() === String(opts.trustedRootHex).replace(/^sha256:/, '').toLowerCase());
      const ok = mres.ok && rootMatch && trustedMatch;
      const detail = !mres.ok ? ('Merkle inclusion failed: ' + mres.reason)
        : (!rootMatch ? "reconstructed root does not equal this binding's anchored_hash"
          : (!trustedMatch ? "reconstructed root does not equal the uploaded checkpoint's root"
            : 'leaf included; reconstructed root matches anchored_hash' + (opts.trustedRootHex ? ' and the checkpoint root' : '')));
      anchorResults.push({ type: ab.type || 'unknown', mode: 'merkle_inclusion', pass: ok, detail, reconstructed_root: mres.ok ? mres.rootHex : null });
    } else {
      const directOk = anchoredHashHex !== '' && anchoredHashHex === recomputed.toLowerCase();
      anchorResults.push({ type: ab.type || 'unknown', mode: 'direct', pass: directOk, detail: directOk ? 'anchored_hash equals recomputed execution_hash (direct anchor — the underlying TST/OTS/tlog-proof evidence bytes are NOT independently re-verified by this tool)' : 'anchored_hash does NOT equal recomputed execution_hash' });
    }
  }
  const anchorsOk = anchorResults.every((r) => r.pass);
  if (anchorBindings.length > 0) {
    checks.push({ check: 'anchor_bindings', pass: anchorsOk, detail: anchorsOk ? (anchorBindings.length + ' anchor binding(s) verify') : 'one or more anchor bindings failed verification' });
  } else if (opts.requireAnchor) {
    checks.push({ check: 'anchor_bindings', pass: false, detail: 'no anchor_bindings present — snapshot-batch mode requires a merkle_inclusion binding to check against the checkpoint' });
  }

  // Staleness (§A0): an anchor binding whose checkpoint predates generated_at, or whose
  // valid_until has passed, is flagged — informational, does not fail the check run by itself.
  const staleNotes = [];
  const genAt = artifact.generated_at ? Date.parse(artifact.generated_at) : NaN;
  for (const ab of anchorBindings) {
    if (ab.valid_until && Date.parse(ab.valid_until) < Date.now()) staleNotes.push('anchor_bindings[] entry (' + (ab.type || 'unknown') + ') valid_until has passed');
  }
  if (staleNotes.length) checks.push({ check: 'anchor_staleness', pass: true, detail: staleNotes.join('; ') + ' (informational — not a FAIL by itself)' });

  const overall = hashMatch && (!sigRes.present || sigRes.allValid) && anchorsOk && (!opts.requireAnchor || anchorBindings.length > 0);
  return { verdict: overall ? 'PASS' : 'FAIL', checks, hash_match: hashMatch, recomputed_hash: recomputed, signature: sigRes, anchors: anchorResults };
}

/* ══════════════════════════════════════════════════════════════
   Disclosure-manifest shape (546-disclosure-manifest-builder /
   547-disclosure-manifest-verifier schema — top-level entries[] +
   merkle_root string, NOT a receipt). Signature-only check: the
   generic verifyArtifactProofs()/securedArtifact() pair operates on
   any JSON object carrying audit_signature.proof, so no new
   canonicalization/hash path is needed for this shape.
══════════════════════════════════════════════════════════════ */
function isDisclosureManifest(obj) {
  return !!(obj && typeof obj === 'object' && Array.isArray(obj.entries) && typeof obj.merkle_root === 'string');
}
async function verifyDisclosureManifest(manifest) {
  const checks = [{ check: 'structure', pass: true, detail: 'disclosure-manifest shape (entries[] + merkle_root) — no §4 execution_hash to recompute' }];
  const sigRes = await verifyArtifactProofs(manifest);
  if (sigRes.present) {
    checks.push({ check: 'audit_signature_proof', pass: sigRes.allValid, detail: sigRes.allValid ? (sigRes.results.length + ' eddsa-jcs-2022 signature(s) verify') : ('signature check failed: ' + sigRes.results.filter((r) => !r.valid).map((r) => r.error).join('; ')) });
  } else {
    checks.push({ check: 'audit_signature_proof', pass: true, detail: 'no §16 signature attached (OPTIONAL — not a failure by itself)' });
  }
  const overall = !sigRes.present || sigRes.allValid;
  return { verdict: overall ? 'PASS' : 'FAIL', checks };
}

/* ══════════════════════════════════════════════════════════════
   Snapshot-batch shape ({checkpoint_note, receipts:[...]}) — the
   same shape 568's batch tab consumes. Each receipt is verified
   against the checkpoint's reconstructed root (requireAnchor:true).
══════════════════════════════════════════════════════════════ */
function isSnapshotBatch(obj) {
  return !!(obj && typeof obj === 'object' && typeof obj.checkpoint_note === 'string' && Array.isArray(obj.receipts));
}
async function verifySnapshotBatch(batch) {
  const cp = parseCheckpointNote(batch.checkpoint_note);
  if (cp.error) return [{ verdict: 'FAIL', checks: [{ check: 'checkpoint_note', pass: false, detail: cp.error }] }];
  const results = [];
  for (const receipt of batch.receipts) {
    results.push(await verifyReceipt(receipt, { requireAnchor: true, trustedRootHex: cp.rootHex }));
  }
  return results;
}

/* ══════════════════════════════════════════════════════════════
   File walk — default glob targets receipt.json files (configurable
   via INPUT_GLOB / OCG_GLOB, see the constant below), plus
   disclosure-manifest / snapshot-batch detection by content shape
   on the same walked JSON files.
══════════════════════════════════════════════════════════════ */
function walk(dir, out) {
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    if (e.name === '.git' || e.name === 'node_modules') continue;
    const full = join(dir, e.name);
    if (e.isDirectory()) walk(full, out);
    else if (e.isFile() && e.name.endsWith('.json')) out.push(full);
  }
  return out;
}
function globSuffixMatches(fileName, glob) {
  // Only the documented default (**/*.receipt.json) and simple *.<ext>.json
  // globs are supported — no full glob engine, to keep this zero-dep.
  const suffix = glob.replace(/^\*\*\//, '').replace(/^\*/, '');
  return fileName.endsWith(suffix.replace(/^\*/, ''));
}

async function main() {
  const root = process.cwd();
  const glob = process.env.INPUT_GLOB || process.env.OCG_GLOB || '**/*.receipt.json';
  const allJson = walk(root, []);
  const rows = []; // {file, tool_id, verdict, checks}
  let anyFail = false;
  let found = 0;

  for (const full of allJson) {
    const rel = relative(root, full).split('\\').join('/');
    const isReceiptGlob = globSuffixMatches(rel, glob);
    let parsed;
    try { parsed = JSON.parse(readFileSync(full, 'utf8')); } catch (e) {
      if (isReceiptGlob) { found++; rows.push({ file: rel, tool_id: '?', verdict: 'FAIL', checks: [{ check: 'structure', pass: false, detail: 'invalid JSON: ' + e.message }] }); anyFail = true; }
      continue;
    }

    if (isReceiptGlob && parsed && parsed.policy_parameters && parsed.output_payload && parsed.execution_hash) {
      found++;
      const report = await verifyReceipt(parsed);
      if (report.verdict !== 'PASS') anyFail = true;
      rows.push({ file: rel, tool_id: parsed.tool_id || '?', verdict: report.verdict, checks: report.checks });
    } else if (isSnapshotBatch(parsed)) {
      const reports = await verifySnapshotBatch(parsed);
      reports.forEach((report, i) => {
        found++;
        if (report.verdict !== 'PASS') anyFail = true;
        const toolId = (parsed.receipts[i] && parsed.receipts[i].tool_id) || '?';
        rows.push({ file: rel + ' [entry ' + i + ']', tool_id: toolId, verdict: report.verdict, checks: report.checks });
      });
    } else if (isDisclosureManifest(parsed)) {
      found++;
      const report = await verifyDisclosureManifest(parsed);
      if (report.verdict !== 'PASS') anyFail = true;
      rows.push({ file: rel, tool_id: 'disclosure-manifest v' + (parsed.version || '?'), verdict: report.verdict, checks: report.checks });
    }
  }

  const pass = rows.filter((r) => r.verdict === 'PASS').length;
  const fail = rows.filter((r) => r.verdict === 'FAIL').length;

  const lines = [];
  lines.push('## ocg-verify-action');
  if (found === 0) {
    lines.push('', '0 receipts found (glob: `' + glob + '`).');
  } else {
    lines.push('', pass + ' pass / ' + fail + ' fail / ' + found + ' found', '', '| file | tool_id | verdict | checks |', '|---|---|---|---|');
    for (const r of rows) {
      const checksStr = r.checks.map((c) => (c.pass === null ? '⏭' : c.pass ? '✓' : '✗') + ' ' + c.check).join(', ');
      lines.push('| ' + r.file + ' | ' + r.tool_id + ' | ' + r.verdict + ' | ' + checksStr + ' |');
    }
  }
  const summary = lines.join('\n') + '\n';
  process.stdout.write(summary);
  if (process.env.GITHUB_STEP_SUMMARY) {
    try { appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary); } catch { /* not fatal outside CI */ }
  }

  process.exitCode = anyFail ? 1 : 0;
}

main().catch((e) => { console.error('ocg-verify-action: fatal: ' + e.stack); process.exitCode = 1; });

export { verifyReceipt, verifyArtifactProofs, verifyMerkleInclusion, executionHash, cgCanon, verifyDisclosureManifest, verifySnapshotBatch, isDisclosureManifest, isSnapshotBatch };
