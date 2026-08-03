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

console.log('\n' + (failures === 0 ? 'A7 fixtures: ALL PASS' : failures + ' FIXTURE ASSERTION(S) FAILED'));
process.exit(failures === 0 ? 0 : 1);
