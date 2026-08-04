# ocg-verify-action

Verify [OpenChainGraph](https://ainumbers.co/chaingraph/standard/SPEC.md) (OCG) receipts and disclosure manifests in CI. On `push` / `pull_request`, it walks the repository for receipt files, recomputes each `execution_hash`, verifies any `eddsa-jcs-2022` signature, and reconstructs any RFC 6962 Merkle inclusion proof — the same checks the browser-based [OCG Receipt Verifier](https://ainumbers.co/tools/568-ocg-receipt-verifier.html) runs, ported to Node so a repository's CI can enforce them automatically.

Zero npm dependencies. `dist/verify.mjs` is committed pre-vendored — no install step, nothing to audit beyond this one file.

## Usage

```yaml
- uses: PostOakLabs/ocg-verify-action@v1
  with:
    glob: '**/*.receipt.json'   # optional, this is the default
```

Disclosure-manifest files (top-level `entries[]` + `merkle_root`, the shape produced by `546-disclosure-manifest-builder`/verified by `547-disclosure-manifest-verifier`) and snapshot-batch files (`{checkpoint_note, receipts[]}`) are detected by content shape and checked regardless of the `glob` input.

## What it checks

| Check | What it proves |
|---|---|
| `structure` | The file has `policy_parameters`, `output_payload`, and a string `execution_hash`. |
| `execution_hash_recompute` | Recomputing the hash over the canonicalized `{policy_parameters, output_payload}` (RFC 8785/JCS) matches the stated `execution_hash` — the payload was not altered after signing/anchoring. |
| `audit_signature_proof` | Any `audit_signature.proof` (`eddsa-jcs-2022` DataIntegrityProof) verifies against its `did:key` verification method. |
| `anchor_bindings` | Each `anchor_bindings[]` entry's Merkle inclusion path (RFC 6962) reconstructs to a root matching `anchored_hash` (and, in snapshot-batch mode, the checkpoint's root). |
| `anchor_staleness` | Informational: flags an anchor binding whose `valid_until` has passed. Does not fail the run by itself. |
| `compute_proof` | For `receiptFormat:"groth16-bn254"`: verifies the BN254 Groth16 pairing equation against the published risc0 verifying key (§18.1) — ported byte-for-byte from `chaingraph/kernels/_computeproof.mjs`'s `verifySeal()`. For any other `receiptFormat` (e.g. `"stark"`, which §18.1 itself delegates to the vendor verifier), the check reports `pass:null` with an explicit skip note — never a false PASS or false FAIL on a check that did not run. |

The check run fails (exit code 1) if any file is FAIL or malformed. If the glob matches zero files, the run passes with "0 receipts found" — adopting this Action before a repo's first receipt exists shouldn't red the build.

No coverage percentage is ever reported — only raw counts (`N pass / M fail / K found`).

## A note on file layout vs. the build spec

`CI-VERIFY-BUILD-SPEC.md` §A1 sketches a repo shape with separate `kernels/_hash.mjs` / `kernels/_proof.mjs` / `kernels/_computeproof.mjs` files. This build instead vendors the needed math directly into `dist/verify.mjs`, per §A1's own instruction: *"copy the browser tool's verified implementation byte-for-byte"* from `tools/568-ocg-receipt-verifier.html`. The repo's actual `chaingraph/kernels/_proof.mjs` now also carries the vendored §PQC-1 ML-DSA machinery (unrelated to v1's `eddsa-jcs-2022`-only scope) — copying that file verbatim would pull in ~3,000 lines this Action never exercises. `dist/verify.mjs` is the single, minimal, already-proven port.

**A6 (§18 compute-proof) exception:** the BN254 Groth16 pairing math is large enough (elliptic-curve field arithmetic, not something to reimplement) that it is vendored as its own file, `dist/vendor/_noble-bn254.bundle.mjs` — an exact copy of `chaingraph/kernels/_noble-bn254.bundle.mjs`, itself a self-contained bundle with **zero further imports** (confirmed: no `import`/`from"..."` statements anywhere in the file). `dist/verify.mjs` imports it locally; there is still no `package.json`, no npm install step, and no dependency an adopter has to trust beyond this repo's own committed files.

## Where the verify logic comes from

`dist/verify.mjs` is ported, math byte-for-byte, from the browser-verified implementation in [`tools/568-ocg-receipt-verifier.html`](https://github.com/PostOakLabs/ainumbers/blob/main/tools/568-ocg-receipt-verifier.html) (canon/hash, `eddsa-jcs-2022` verify, RFC 6962 Merkle inclusion, checkpoint-note parsing). Only the I/O layer is new — file walk instead of paste/upload, a job-summary table instead of a DOM render. This Action does not re-derive canonicalization or signature math from spec text; it reuses the already-shipped, already-gated implementation so the two can never drift independently.

Node's built-in `crypto.webcrypto` (`globalThis.crypto.subtle`) is used exactly as the browser tool uses `crypto.subtle` — same API surface, no behavior change. Requires **Node 20+** (Ed25519 `crypto.subtle` support).

## Security shape

This Action **only reads and reports** — it never writes back to the repository or the pull request. No PR comment, no label application, no `gh pr edit`, no other repo-write side effect of any kind. The job summary (`$GITHUB_STEP_SUMMARY`) and the exit code are the only outputs.

**Fork PRs:** this Action triggers on plain `pull_request` (never `pull_request_target`, never `workflow_run`), so a fork PR gets only the platform's automatic read-only token and no secrets — which is fine, because the Action needs neither. The checkout is the PR head. Unlike a workflow that *executes* fork content (where checking out only the base ref is the standard defense — see the AGENTPR-1 shape this repo's sibling tooling reuses), `ocg-verify-action` never executes the receipt JSON it reads; it only parses it as data through the vendored verifier above. **Do not cargo-cult the checkout-base-only pattern here** — it solves a different problem than the one this Action has.

Every input that reaches a shell command goes through `env:` + `$VAR`, never inline `${{ }}` interpolation, per the standard zizmor template-injection rule (see `action.yml`).

This repository's own `.github/workflows/ci.yml` (testing the Action against its fixtures) is a same-repo trusted workflow, not fork-triggered, so it uses ordinary `pull_request` + full checkout without the fork caveats above — those apply only to *consumers'* usage of the published Action.

## Fixtures

`fixtures/` contains three cases reused verbatim from `568-ocg-receipt-verifier`'s own fixture block (a real Ed25519-signed, RFC 6962 Merkle-included round-trip, generated offline via the shared `_hash.mjs`/`_proof.mjs`/`_anchor-testutil.mjs` kernels):

- `golden.receipt.json` — verifies PASS.
- `tampered.receipt.json` — `output_payload.decision` mutated after signing; verifies FAIL with the correct `execution_hash_recompute` detail.
- `snapshot-batch.json` — two receipts checked against a shared checkpoint root; both verify PASS with correct per-entry verdicts.
- `compute-proof-golden.receipt.json` — a real `RISC0_DEV_MODE=0` groth16-bn254 receipt (the same fixture `chaingraph/kernels/compute-proof.test.mjs` gates on, `fixtures/compute-proof/art-04-agent-identity-attestation-checker.receipt.json`) attached to its matching artifact; verifies PASS with `compute_proof: pass:true`.
- `compute-proof-tampered.receipt.json` — the same receipt with one seal byte flipped; verifies FAIL with `compute_proof: pass:false` specifically (all other checks still pass — this isolates the pairing-math port from the hash/signature checks).

`test/run-fixtures.mjs` asserts all cases directly against `dist/verify.mjs`'s exported functions (`node test/run-fixtures.mjs`) — this is the port's correctness gate: green here proves the Node port matches the browser-verified/kernel-verified logic without re-deriving trust from spec text alone, on BOTH the hash/signature/Merkle math (A7, golden fixture set) and the BN254 pairing math (A6, compute-proof fixture set — a real proof PASSes, a tampered one FAILs). It also asserts a non-groth16-bn254 `receiptFormat` (e.g. `"stark"`) is honestly skipped rather than false-PASSed or false-FAILed. `.github/workflows/ci.yml` also runs the Action against its own fixtures end-to-end and asserts it reports the expected failure.

## Non-goals

- No PR comments, labels, or any repo-write side effect.
- No coverage-percentage reporting.
- No verification of `receiptFormat:"stark"` compute proofs — §18.1 itself delegates stark seal verification to the vendor verifier; this Action reports an honest skip for that format, same as the underlying kernel.
