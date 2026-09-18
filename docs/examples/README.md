# AMPEL Examples

Four small, self-contained examples. Each directory holds a policy and the
attestation it reads, so every one of them runs as-is with no network access
and no collectors configured.

All four describe the same imaginary artifact, so they share one subject
digest:

```shell
export SUBJECT=sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

The attestations are unsigned, which is fine for a demo but not for real life.
AMPEL prints a warning about it and admits them because they were passed
explicitly with `-a`; in production you would set `identities` on the policy
and let AMPEL verify the signatures.

| Example | What it shows |
| --- | --- |
| [`sbom/`](sbom) | A plain policy with three tenets, reading an SBOM |
| [`custom-predicate/`](custom-predicate) | Writing policy against a predicate type AMPEL knows nothing about |
| [`policyset/`](policyset) | A PolicySet: several policies sharing context, mapped to framework controls |
| [`group/`](group) | A PolicyGroup: blocks of _alternative_ policies |

## 1. Checking an SBOM

[`sbom/sbom-checks.hjson`](sbom/sbom-checks.hjson) is the simplest shape a
policy takes: an id, some metadata, the predicate types it wants, and a list
of tenets. The three tenets check that every package in the SBOM declares a
license, that those licenses are on an allowed list, and that a specific
dependency is present, looked up by its package URL.

```shell
ampel verify -s $SUBJECT \
  -p docs/examples/sbom/sbom-checks.hjson \
  -a docs/examples/sbom/sbom.spdx.intoto.json
```

The policy names both the SPDX and the CycloneDX predicate types, so the same
code works against an SBOM in either format.

## 2. A made up predicate

AMPEL has native support for well known attestation types, but it does not
need to know anything about a predicate to run policy on it.
[`custom-predicate/code-review.hjson`](custom-predicate/code-review.hjson)
reads an invented `https://example.com/attestations/code-review/v1` predicate
and checks that a change was approved by two people other than its author.

```shell
ampel verify -s $SUBJECT \
  -p docs/examples/custom-predicate/code-review.hjson \
  -a docs/examples/custom-predicate/code-review.intoto.json
```

Name the type in the policy's `predicates` block and the predicate JSON shows
up in the runtime under `predicates[0].data`, untouched.

## 3. A PolicySet verifying SLSA provenance

[`policyset/slsa-build.hjson`](policyset/slsa-build.hjson) bundles three
policies that check the SLSA provenance of the artifact: that it was built by
the expected builder, through the expected build type, and from the expected
source repository.

```shell
ampel verify -s $SUBJECT \
  -p docs/examples/policyset/slsa-build.hjson \
  -a docs/examples/policyset/provenance.intoto.json
```

The set's `common` block defines the expected builder, build type and
repository once, and all three policies read them as `context.*`. That is what
makes the policies reusable — point the set at a different project by
overriding a value on the command line instead of editing the file:

```shell
ampel verify -s $SUBJECT \
  -p docs/examples/policyset/slsa-build.hjson \
  -a docs/examples/policyset/provenance.intoto.json \
  --context="sourceRepo:https://github.com/example/other-project"
```

That run fails, which is the point.

Each policy also maps itself to a SLSA control through `meta.controls`, so the
results table gets a Controls column. The policies in the
[carabiner-dev/policies](https://github.com/carabiner-dev/policies) repository
are organized the same way, except that the sets there reference their
policies remotely by commit rather than inlining them.

## 4. A PolicyGroup, or: blocks are alternatives

[`group/breakfast.hjson`](group/breakfast.hjson) is deliberately silly, because
the structure is the only thing worth remembering:

- a group is a list of **blocks**, and every block is a requirement
- a block is a list of **alternative** policies that can satisfy it

Blocks combine with AND, policies inside a block with OR. This group asks for
something to drink AND something to eat, and accepts coffee OR tea for the
first, toast OR cereal for the second.

```shell
ampel verify -s $SUBJECT \
  -p docs/examples/group/breakfast.hjson \
  -a docs/examples/group/breakfast.intoto.json
```

The attestation records coffee and toast, so both blocks pass. Edit it to
serve orange juice instead and the drinks block fails while the food block
keeps passing — one failed requirement is enough to fail the group.
