#!/usr/bin/env node
// A7 conformance gate: golden -> PASS, tampered -> FAIL (execution_hash_recompute detail),
// snapshot-batch -> correct per-entry verdicts. Asserts against dist/verify.mjs directly
// (no shell round-trip) so a failure here points straight at the ported logic.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { verifyReceipt, verifySnapshotBatch } from '../dist/verify.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, '..', 'fixtures');
const golden = JSON.parse(readFileSync(join(fixturesDir, 'golden.receipt.json'), 'utf8'));
const tampered = JSON.parse(readFileSync(join(fixturesDir, 'tampered.receipt.json'), 'utf8'));
const batch = JSON.parse(readFileSync(join(fixturesDir, 'snapshot-batch.json'), 'utf8'));
const cpGolden = JSON.parse(readFileSync(join(fixturesDir, 'compute-proof-golden.receipt.json'), 'utf8'));
const cpTampered = JSON.parse(readFileSync(join(fixturesDir, 'compute-proof-tampered.receipt.json'), 'utf8'));

let failures = 0;
function assert(cond, msg) { if (!cond) { failures++; console.error('FAIL: ' + msg); } else { console.log('ok: ' + msg); } }

const goldenReport = await verifyReceipt(golden);
assert(goldenReport.verdict === 'PASS', 'golden fixture verdict is PASS (got ' + goldenReport.verdict + ')');

const tamperedReport = await verifyReceipt(tampered);
assert(tamperedReport.verdict === 'FAIL', 'tampered fixture verdict is FAIL (got ' + tamperedReport.verdict + ')');
const hashCheck = tamperedReport.checks.find((c) => c.check === 'execution_hash_recompute');
assert(hashCheck && hashCheck.pass === false, 'tampered fixture fails execution_hash_recompute specifically');
assert(hashCheck && /does NOT match/.test(hashCheck.detail), 'tampered fixture failure detail names the hash mismatch (got: ' + (hashCheck && hashCheck.detail) + ')');

const batchReports = await verifySnapshotBatch(batch);
assert(batchReports.length === 2, 'snapshot-batch produced 2 per-entry reports (got ' + batchReports.length + ')');
assert(batchReports[0] && batchReports[0].verdict === 'PASS', 'snapshot-batch entry 0 verdict is PASS (got ' + (batchReports[0] && batchReports[0].verdict) + ')');
assert(batchReports[1] && batchReports[1].verdict === 'PASS', 'snapshot-batch entry 1 verdict is PASS (got ' + (batchReports[1] && batchReports[1].verdict) + ')');

// ── A6 — §18.1 groth16-bn254 compute_proof seal verification (port of _computeproof.mjs) ──
// Golden fixture carries a REAL RISC0_DEV_MODE=0 receipt (repo/chaingraph/kernels/fixtures/
// compute-proof/art-04-agent-identity-attestation-checker.receipt.json) attached to a matching
// artifact — green here means the ported pairing math actually verified a real zkVM proof, not
// just structure. Tampered fixture flips one seal byte — same fixture-generation shape as A7.
const cpGoldenReport = await verifyReceipt(cpGolden);
assert(cpGoldenReport.verdict === 'PASS', 'compute-proof golden fixture verdict is PASS (got ' + cpGoldenReport.verdict + ')');
const cpGoldenCheck = cpGoldenReport.checks.find((c) => c.check === 'compute_proof');
assert(cpGoldenCheck && cpGoldenCheck.pass === true, 'compute-proof golden fixture: compute_proof check reports pass:true (got ' + (cpGoldenCheck && cpGoldenCheck.pass) + ')');

const cpTamperedReport = await verifyReceipt(cpTampered);
assert(cpTamperedReport.verdict === 'FAIL', 'compute-proof tampered fixture verdict is FAIL (got ' + cpTamperedReport.verdict + ')');
const cpTamperedCheck = cpTamperedReport.checks.find((c) => c.check === 'compute_proof');
assert(cpTamperedCheck && cpTamperedCheck.pass === false, 'compute-proof tampered fixture fails the compute_proof check specifically (got ' + (cpTamperedCheck && cpTamperedCheck.pass) + ')');
assert(cpTamperedCheck && /does NOT verify/.test(cpTamperedCheck.detail), 'compute-proof tampered failure detail names the seal mismatch (got: ' + (cpTamperedCheck && cpTamperedCheck.detail) + ')');

// non-groth16-bn254 receiptFormat still SKIPS honestly (never a false PASS or a FAIL on a check not run).
const cpStark = JSON.parse(JSON.stringify(cpGolden));
cpStark.audit_signature.compute_proof.receiptFormat = 'stark';
const cpStarkReport = await verifyReceipt(cpStark);
const cpStarkCheck = cpStarkReport.checks.find((c) => c.check === 'compute_proof');
assert(cpStarkCheck && cpStarkCheck.pass === null, 'stark receiptFormat is reported as a skip (pass:null), never verified/failed by this Action version (got ' + (cpStarkCheck && cpStarkCheck.pass) + ')');
assert(cpStarkReport.verdict === 'PASS', 'a skipped (stark) compute_proof check does not fail the overall verdict (got ' + cpStarkReport.verdict + ')');

console.log('\n' + (failures === 0 ? 'A7/A6 fixtures: ALL PASS' : failures + ' FIXTURE ASSERTION(S) FAILED'));
process.exit(failures === 0 ? 0 : 1);
