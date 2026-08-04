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
import { bn254, sha256 as nobleSha256 } from './vendor/_noble-bn254.bundle.mjs';

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
   §A6 / §18.1 — self-contained BN254 Groth16 reference verifier for
   receiptFormat:"groth16-bn254", ported verbatim (math untouched,
   only the cgCanon import point adjusted to this file's own cgCanon)
   from repo/chaingraph/kernels/_computeproof.mjs. Per CIVERIFY-A6-1:
   "port it and prove the port matches" — no re-derivation from spec
   text, no "improved" math. verifySeal() below is byte-for-byte the
   same algorithm as the kernel's verifySeal(); only the module-load
   plumbing (import path, no `attachComputeProof`/`verifyBinding`
   re-export — the Action only needs the seal check) differs.
══════════════════════════════════════════════════════════════ */
const { G1, G2, fields, pairingBatch } = bn254;
const Fp12 = fields.Fp12;

// risc0 default verifier parameters (v3.0.x), as 32-byte digests (Digest::as_bytes order).
const CONTROL_ROOT_HEX = 'a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56';
const BN254_CONTROL_ID_HEX = 'c07a65145c3cb48b6101962ea607a4dd93c753bb26975cb47feb00d3666e4404';

// risc0 Groth16 verifying key (decimal field coordinates).
const VK = {
  alpha: ['20491192805390485299153009773594534940189261866228447918068658471970481763042',
          '9383485363053290200918347156157836566562967994039712273449902621266178545958'],
  beta:  ['6375614351688725206403948262868962793625744043794305715222011528459656738731',
          '4252822878758300859123897981450591353533073413197771768651442665752259397132',
          '10505242626370262277552901082094356697409835680220590971873171140371331206856',
          '21847035105528745403288232691147584728191162732299865338377159692350059136679'],
  gamma: ['10857046999023057135944570762232829481370756359578518086990519993285655852781',
          '11559732032986387107991004021392285783925812861821192530917403151452391805634',
          '8495653923123431417604973247489272438418190587263600148770280649306958101930',
          '4082367875863433681332203403145435568316851327593401208105741076214120093531'],
  delta: ['12043754404802191763554326994664886008979042643626290185762540825416902247219',
          '1668323501672964604911431804142266013250380587483576094566949227275849579036',
          '13740680757317479711909903993315946540841369848973133181051452051592786724563',
          '7710631539206257456743780535472368339139328733484942210876916214502466455394'],
  IC: [
    ['8446592859352799428420270221449902464741693648963397251242447530457567083492','1064796367193003797175961162477173481551615790032213185848276823815288302804'],
    ['3179835575189816632597428042194253779818690147323192973511715175294048485951','20895841676865356752879376687052266198216014795822152491318012491767775979074'],
    ['5332723250224941161709478398807683311971555792614491788690328996478511465287','21199491073419440416471372042641226693637837098357067793586556692319371762571'],
    ['12457994489566736295787256452575216703923664299075106359829199968023158780583','19706766271952591897761291684837117091856807401404423804318744964752784280790'],
    ['19617808913178163826953378459323299110911217259216006187355745713323154132237','21663537384585072695701846972542344484111393047775983928357046779215877070466'],
    ['6834578911681792552110317589222010969491336870276623105249474534788043166867','15060583660288623605191393599883223885678013570733629274538391874953353488393'],
  ],
};

const cpEnc = (s) => new TextEncoder().encode(s);
const cpHexToBytes = (h) => Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16)));
const cpIntBE = (b) => b.reduce((a, x) => (a << 8n) + BigInt(x), 0n);
const cpIntLE = (b) => cpIntBE(Uint8Array.from(b).reverse());
const cpU32le = (n) => Uint8Array.from([n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff]);
const cpU16le = (n) => Uint8Array.from([n & 0xff, (n >> 8) & 0xff]);
const cpConcat = (arrs) => { const t = []; for (const a of arrs) for (const b of a) t.push(b); return Uint8Array.from(t); };
const CP_ZERO32 = new Uint8Array(32);

// risc0 tagged_struct: sha256( sha256(tag) || down... || data(LE u32)... || u16le(down.len) ).
function taggedStruct(tag, down, data) {
  return nobleSha256(cpConcat([nobleSha256(cpEnc(tag)), ...down, ...data.map(cpU32le), cpU16le(down.length)]));
}

// risc0 ReceiptClaim::ok(image_id, journal).digest() — the claim a halted-0, no-assumptions receipt commits.
function claimDigestOk(imageIdBytes, journalBytes) {
  const post = taggedStruct('risc0.SystemState', [CP_ZERO32], [0]);
  const output = taggedStruct('risc0.Output', [nobleSha256(journalBytes), CP_ZERO32], []);
  return taggedStruct('risc0.ReceiptClaim', [CP_ZERO32, imageIdBytes, post, output], [0, 0]);
}

// split_digest(d) -> [Fr(low 16B), Fr(high 16B)] (big-endian interpretation).
function splitDigest(bytes32) {
  const be = Uint8Array.from(bytes32).reverse();
  return [cpIntBE(be.slice(16, 32)), cpIntBE(be.slice(0, 16))];
}

const cpG1 = ([x, y]) => G1.Point.fromAffine({ x: BigInt(x), y: BigInt(y) });
const cpG2 = ([x0, x1, y0, y1]) => G2.Point.fromAffine({ x: { c0: BigInt(x0), c1: BigInt(x1) }, y: { c0: BigInt(y0), c1: BigInt(y1) } });

function cpNormId(d) { return typeof d === 'string' && d.startsWith('sha256:') ? d : 'sha256:' + d; }

/**
 * §18.1 — verify a risc0 Groth16-BN254 receipt's cryptographic seal, self-contained and chain-free.
 * Same contract as the kernel's verifySeal(): true iff the proof verifies for the ReceiptClaim derived
 * from (imageId, canonical journal); throws (delegated) for receiptFormat:'stark'; false on any
 * structural problem or invalid proof.
 */
function verifySeal(receipt) {
  const cp = receipt;
  if (!cp || typeof cp !== 'object') return false;
  if (cp.receiptFormat === 'stark') {
    throw new Error('§18.1: stark seal verification is DELEGATED to the vendor verifier (e.g. risc0-verifier); ' +
      'OCG ships only the self-contained BN254 Groth16 reference verifier for receiptFormat:"groth16-bn254".');
  }
  if (cp.receiptFormat !== 'groth16-bn254') return false;
  if (typeof cp.imageId !== 'string' || typeof cp.seal !== 'string') return false;
  if (!cp.journal || typeof cp.journal !== 'object') return false;

  const journalBytes = cpEnc(JSON.stringify(cgCanon(cp.journal)));
  const imageIdBytes = cpHexToBytes(cpNormId(cp.imageId).slice('sha256:'.length));
  if (imageIdBytes.length !== 32) return false;
  const claimDigest = claimDigestOk(imageIdBytes, journalBytes);
  const [a0, a1] = splitDigest(cpHexToBytes(CONTROL_ROOT_HEX));
  const [c0, c1] = splitDigest(claimDigest);
  const idBn254 = cpIntLE(cpHexToBytes(BN254_CONTROL_ID_HEX));
  const pub = [a0, a1, c0, c1, idBn254];

  let seal;
  try { seal = Uint8Array.from(atob(cp.seal), (ch) => ch.charCodeAt(0)); } catch { return false; }
  if (seal.length !== 256) return false;
  let A, B, C, vkx;
  try {
    A = G1.Point.fromAffine({ x: cpIntBE(seal.slice(0, 32)), y: cpIntBE(seal.slice(32, 64)) });
    B = G2.Point.fromAffine({
      x: { c0: cpIntBE(seal.slice(96, 128)), c1: cpIntBE(seal.slice(64, 96)) },
      y: { c0: cpIntBE(seal.slice(160, 192)), c1: cpIntBE(seal.slice(128, 160)) },
    });
    C = G1.Point.fromAffine({ x: cpIntBE(seal.slice(192, 224)), y: cpIntBE(seal.slice(224, 256)) });
    A.assertValidity(); B.assertValidity(); C.assertValidity();
    const IC = VK.IC.map(cpG1);
    vkx = IC[0];
    for (let i = 0; i < pub.length; i++) vkx = vkx.add(IC[i + 1].multiply(pub[i]));
  } catch { return false; }

  try {
    const gt = pairingBatch([
      { g1: A, g2: B },
      { g1: cpG1(VK.alpha).negate(), g2: cpG2(VK.beta) },
      { g1: vkx.negate(), g2: cpG2(VK.gamma) },
      { g1: C.negate(), g2: cpG2(VK.delta) },
    ]);
    return Fp12.eql(gt, Fp12.ONE);
  } catch { return false; }
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

  // §A6/§18.1: verify audit_signature.compute_proof when receiptFormat is one this Action
  // ships a verifier for (groth16-bn254). Any other receiptFormat (e.g. "stark", which §18.1
  // itself delegates to the vendor verifier) still SKIPS honestly rather than false-PASS/FAIL.
  let cpRes = null;
  const cp = artifact.audit_signature && artifact.audit_signature.compute_proof;
  if (cp && typeof cp === 'object') {
    if (cp.receiptFormat === 'groth16-bn254') {
      let sealOk = false, sealErr = null;
      try { sealOk = verifySeal(cp); } catch (e) { sealErr = e.message; }
      cpRes = sealOk;
      checks.push({ check: 'compute_proof', pass: sealOk, detail: sealErr ? ('compute_proof seal verification errored: ' + sealErr) : (sealOk ? 'groth16-bn254 seal verifies against the risc0 verifying key (§18.1)' : 'groth16-bn254 seal does NOT verify — proof is invalid or was tampered with') });
    } else {
      checks.push({ check: 'compute_proof', pass: null, detail: 'compute_proof present with receiptFormat "' + cp.receiptFormat + '" — not verified by this Action version (only groth16-bn254 is supported; stark stays vendor-delegated per §18.1)' });
    }
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

  const overall = hashMatch && (!sigRes.present || sigRes.allValid) && anchorsOk && (!opts.requireAnchor || anchorBindings.length > 0) && cpRes !== false;
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
