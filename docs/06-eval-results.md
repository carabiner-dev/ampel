# Evaluation Results

When AMPEL finishes evaluating a policy, the verdict needs to go somewhere.
This document explains the result structures the verifier produces internally,
the output drivers that render them for humans and machines, how results can be
captured as attestations and how those attestations can be signed.

## The Result Structures

Internally, the verifier mirrors the structure of the policy it evaluates.
Every layer of a policy produces a matching result type:

- **EvalResult**: The evaluation result of a single tenet. It records the
  tenet's PASS/FAIL/SOFTFAIL status, the attested statements that were used as
  evidence, any output values the tenet code computed and the resulting
  assessment (when it passes) or error (when it fails).
- **Result**: The result of evaluating one policy. It aggregates the
  EvalResults of the policy's tenets into a single status, together with the
  policy identifier, its metadata and the evaluation context values in effect.
- **ResultGroup**: The result of a [policy group](05-policy-groups.md). It
  collects the results of the policies in the group's blocks and computes the
  group status according to the group's assertion mode.
- **ResultSet**: The result of the whole run. It contains a Result for each
  policy in the PolicySet, a ResultGroup for each group, the subject under
  evaluation and the overall status. Even a run with a single policy produces
  a ResultSet wrapping one Result.

Every level carries one of three status labels: `PASS`, `FAIL` or `SOFTFAIL`.
Soft failures occur when a failing policy is not enforced (its `enforce` mode
is off) or when the engine is instructed to tolerate missing runtimes or
plugins (`--skip-unsupported-runtime`).

## Output Drivers

The verifier renders results through pluggable output drivers, selected with
the `--format` (`-f`) flag of `ampel verify`:

```bash
ampel verify binary.exe -p policy.json -a attestation.intoto.json --format=summary
```

These are the supported drivers:

| Format | Output |
| --- | --- |
| `tty` | Colored tables for the terminal (the default). |
| `html` | The results tables as HTML, ready to embed in web pages or CI job summaries. |
| `markdown` | The results tables as markdown. |
| `summary` | A single traffic-light line (🔴🟡🟢) summarizing the run, ideal for compact destinations such as the GitHub Actions step summary. |
| `attestation` | The results as an unsigned in-toto attestation statement. |
| `vsa` | The results as a [SLSA Verification Summary Attestation](https://slsa.dev/spec/v1.0/verification_summary). |
| `svr` | The results as a [Simple Verification Result](https://github.com/in-toto/attestation/blob/main/spec/predicates/svr.md) attestation. |

The available formats are listed in the `ampel verify --help` output, the list
is generated from the registered drivers so it is always up to date.

## Attesting the Results

Independent of the output rendered above, AMPEL can capture the evaluation
results as an attestation. This is how a policy verdict becomes evidence:
downstream tooling (including AMPEL itself) can consume the results
attestation to gate later stages without re-running the evaluation.

To attest the results of an evaluation, pass `--attest-results`:

```bash
ampel verify binary.exe -p policy.json -a attestation.intoto.json \
    --attest-results --results-path=results.intoto.json
```

The attestation is written to the file specified with `--results-path`
(`results.intoto.json` by default). The predicate format is controlled with
`--attest-format`:

- **`ampel`** (default): The full ResultSet described above, using the
  `https://carabiner.dev/ampel/resultset/v0` predicate type. This is the
  richest format, it preserves every policy, tenet and message.
- **`vsa`**: A [SLSA Verification Summary Attestation](https://slsa.dev/spec/v1.0/verification_summary),
  the standard summary format for policy verdicts in the SLSA ecosystem.
- **`svr`**: A [Simple Verification Result](https://github.com/in-toto/attestation/blob/main/spec/predicates/svr.md),
  a minimal in-toto predicate (`https://in-toto.io/attestation/svr/v0.1`)
  that captures the verdict without the evaluation detail.

## Signing the Results Attestations

A results attestation is only as trustworthy as its signature. Passing
`--sign` makes AMPEL sign the attestation it writes:

```bash
ampel verify binary.exe -p policy.json -a attestation.intoto.json \
    --attest-results --sign
```

The signing method is selected with `--signing-backend`:

- **`sigstore`** (default): Keyless signing using an OIDC identity. In
  automation, ambient credentials are picked up automatically (for example,
  the workflow identity token when running in GitHub Actions); interactively,
  AMPEL starts the browser-based OIDC flow. Use `--sigstore-instance` to pick
  the sigstore instance to sign against (`sigstore`, the public good instance,
  is the default; `github` signs against GitHub's Sigstore deployment). By default the signature is
  recorded in the Rekor transparency log (disable with
  `--sigstore-rekor-append=false`).
- **`key`**: Signing with private keys passed with `--signing-key` (`-K`).
  AMPEL reads PEM-encoded PKCS#8, PKCS#1 and SEC1 keys as well as OpenPGP
  keys. If a key is protected by a passphrase, AMPEL reads it from the
  environment variable named by `--signing-key-passphrase-env`
  (`SIGNING_KEY_PASSPHRASE` by default).
- **`spiffe`**: Signing with an identity obtained from a SPIFFE Workload API
  socket (`--spiffe-socket`), optionally enforcing the expected trust domain
  with `--spiffe-trust-domain`.

When signing through sigstore or SPIFFE, AMPEL adds an RFC 3161 timestamp from
a trusted timestamp authority by default (disable with
`--signing-timestamp=false`).

## Writing a New Output Renderer

Output drivers live in `internal/drivers/`, one package per format. A driver
implements the render engine's `Driver` interface:

```golang
type Driver interface {
	RenderResultSet(w io.Writer, status *papi.ResultSet) error
	RenderResult(w io.Writer, status *papi.Result) error
	RenderResultGroup(w io.Writer, status *papi.ResultGroup) error
}
```

The three methods render the result structures described at the top of this
document; each one writes its output to the supplied writer. To make the new
driver available to `--format`, register it under its format name in
`LoadDefaultDrivers()` in `internal/render/render.go` (programs embedding the
engine can also call `render.RegisterDriver()` at runtime). Once registered,
the driver automatically shows up in the format list of the
`ampel verify --help` output.

The `summary` driver is a good starting point to study: it is the smallest of
the built-in drivers and exercises the whole interface.
