# CEL plugins

AMPEL's CEL evaluator ships with a handful of plugins that register
extra globals in every policy expression. The same environment is
used by:

- **Tenet code** (`tenets[].code` in a policy)
- **Chained-subject selectors** (`chain[].predicate.selector`)
- **Context-value expressions** (`context.<name>.expression` at any
  scope — PolicySet, PolicyGroup, or Policy common blocks)

So `semver.satisfies(...)`, `hasher.sha256(...)`, `purl.name(...)`,
etc. all work anywhere CEL runs.

Plugins are registered automatically when `LoadDefaultPlugins: true`
is set on the evaluator options (the default). Callers embedding
AMPEL can opt out and register a smaller set themselves via
`Evaluator.RegisterPlugin`.

- [`hasher`](#hasher) — hash arbitrary strings.
- [`url`](#url) — parse URLs into components.
- [`github`](#github) — parse GitHub repo / branch URIs.
- [`protobom`](#protobom) — query SBOMs attached as predicates.
- [`purl`](#purl) — parse Package URLs.
- [`semver`](#semver) — parse and compare semantic-version strings.

---

## `hasher`

Computes cryptographic digests over string content. Useful when a
tenet needs to confirm that content hashes to an expected value, or
for building quick digest tables inside a context expression.

| Expression                              | Returns  | Description                                |
|:----------------------------------------|:---------|:-------------------------------------------|
| `hasher.sha256("hello")`                | `string` | Hex-encoded SHA-256 digest.                |
| `hasher.sha1("hello")`                  | `string` | Hex-encoded SHA-1 digest. Legacy use only. |
| `hasher.sha512("hello")`                | `string` | Hex-encoded SHA-512 digest.                |

Also exposes a read-only `hashAlgorithms` list holding the supported
algorithm names.

```cel
hasher.sha256(predicate.data.source) == subject.digest.sha256
```

---

## `url`

Parses a URL string into its scheme / host / path / fragment parts.

| Expression                       | Returns                | Description                  |
|:---------------------------------|:-----------------------|:-----------------------------|
| `url.parse("https://example.com/a#b")` | `map<string, string>` | `{scheme, host, path, fragment}`. |

```cel
url.parse(predicate.data.source).host.endsWith("apache.org")
```

Malformed URLs produce a CEL evaluation error.

---

## `github`

Helpers for working with GitHub URIs (as they appear in SLSA
provenance, source descriptors, etc.).

| Expression                                               | Returns               | Description                                       |
|:---------------------------------------------------------|:----------------------|:--------------------------------------------------|
| `github.parseRepo("github.com/owner/repo")`              | `map<string, any>`    | `{org, repo, host, ...}` — legacy helper.         |
| `github.orgDescriptorFromURI("https://github.com/owner")` | `map<string, any>`    | Organisation descriptor (in-toto subject shape).  |
| `github.repoDescriptorFromURI("https://github.com/owner/repo")` | `map<string, any>` | Repository descriptor.                            |
| `github.branchDescriptorFromURI("https://github.com/owner/repo", "main")` | `map<string, any>` | Repo + branch descriptor.                         |

```cel
github.repoDescriptorFromURI(
    predicate.data.buildDefinition.resolvedDependencies[0].uri
).name == "source-tool"
```

---

## `protobom`

Exposes SBOM helpers when the subject carries SPDX or CycloneDX
predicates. The plugin delegates to the
[`protobom/cel` library](https://github.com/protobom/cel), which
defines the `Document`, `Node`, `NodeList`, etc. receiver types and
a rich set of filter/map/query methods on them.

| Variable / expression  | Returns    | Description                                                  |
|:-----------------------|:-----------|:-------------------------------------------------------------|
| `sboms`                | `list`     | All SBOM documents attached to the subject as predicates.    |
| `sboms[i].get_root_nodes()` | `list` | Top-level nodes of document `i`.                             |
| `sboms[i].get_node_list().get_nodes().filter(...)` | `list` | Tree-walk filter over nodes.                                 |

A real policy often looks like this (from the apache-commons
policyset):

```cel
cel.bind(
    root, sboms[0].get_root_nodes()[0],
    sboms[0].get_node_list()
        .get_node_descendants(root.id, 1).get_nodes()
        .filter(n, n.id != root.id)
        .map(n, {
            "name":   n.name,
            "uri":    has(n.identifiers.PURL) ? n.identifiers.PURL : "",
            "digest": n.hashes,
        })
)
```

See the protobom/cel library README for the full list of methods on
each type.

---

## `purl`

Parses a [Package URL](https://github.com/package-url/purl-spec) into
its components.

| Expression                                    | Returns                | Description                                   |
|:----------------------------------------------|:-----------------------|:----------------------------------------------|
| `purl.parse("pkg:maven/org.x/lib@1.0")`       | `map<string, any>`     | Full parse — every component at once.         |
| `purl.packageType("pkg:maven/org.x/lib")`     | `string`               | The `pkg:<type>` portion (e.g. `"maven"`).    |
| `purl.namespace("pkg:maven/org.x/lib")`       | `string`               | The namespace (e.g. `"org.x"`).               |
| `purl.name("pkg:maven/org.x/lib")`            | `string`               | The package name.                             |
| `purl.version("pkg:maven/org.x/lib@1.0")`     | `string`               | The version, if any.                          |
| `purl.qualifiers("pkg:deb?arch=amd64")`       | `map<string, string>`  | The `?key=value` qualifiers.                  |
| `purl.subpath("pkg:npm/@scope/x@1#lib/a.js")` | `string`               | The `#subpath` portion.                       |

```cel
purl.packageType(subject.name) == "maven" &&
purl.namespace(subject.name) == "org.apache.commons"
```

Unparseable PURL strings return a CEL evaluation error.

---

## `semver`

Parses and compares [Semantic Versioning 2.0.0](https://semver.org/)
strings. Accepts versions with or without a leading `v`.

| Expression                                  | Returns  | Description                                                                |
|:--------------------------------------------|:---------|:---------------------------------------------------------------------------|
| `semver.major("1.2.3")`                     | `int`    | Major component.                                                           |
| `semver.minor("1.2.3")`                     | `int`    | Minor component.                                                           |
| `semver.patch("1.2.3")`                     | `int`    | Patch component.                                                           |
| `semver.prerelease("1.2.3-alpha.1")`        | `string` | Pre-release label, or `""`.                                                |
| `semver.build("1.2.3+sha.abc")`             | `string` | Build metadata, or `""`.                                                   |
| `semver.parse("1.2.3-rc+sha")`              | `map`    | `{major, minor, patch, prerelease, build, original}` as a map.             |
| `semver.isValid("v1.2.3")`                  | `bool`   | `true` iff the string parses.                                              |
| `semver.isStable("1.2.3")`                  | `bool`   | `major >= 1` and no pre-release tag.                                       |
| `semver.compare(a, b)`                      | `int`    | `-1` if `a < b`, `0` if equal, `1` if `a > b`.                             |
| `semver.isNewer(a, b)`                      | `bool`   | Shorthand for `compare(a, b) > 0`.                                         |
| `semver.isOlder(a, b)`                      | `bool`   | Shorthand for `compare(a, b) < 0`.                                         |
| `semver.equal(a, b)`                        | `bool`   | Shorthand for `compare(a, b) == 0`.                                        |
| `semver.satisfies(v, constraint)`           | `bool`   | npm-style constraint check (`^1.2.3`, `>=1.0.0 <2.0.0`, `~1.2.0`, `||`, …).|

Wrap with `string(...)` when a numeric component is needed as a
string (e.g. for interpolation):

```cel
string(semver.major(subject.name)) + "." + string(semver.minor(subject.name))
```

Common recipes:

```cel
// Reject builds below a baseline.
semver.satisfies(predicate.data.version, ">=2.0.0 <3.0.0")

// Block pre-releases from promoting to production.
semver.isStable(predicate.data.version)

// Only accept patch bumps over a pinned base.
semver.major(predicate.data.version) == semver.major(context.base) &&
semver.minor(predicate.data.version) == semver.minor(context.base) &&
!semver.isOlder(predicate.data.version, context.base)
```

Invalid version strings (or invalid constraint strings for
`satisfies`) surface as CEL evaluation errors — guard with
`semver.isValid(...)` first if a tenet might receive arbitrary
input.

---

## Adding a plugin

New plugins implement the `Plugin` interface from
`pkg/api/v1` (`Capabilities`, `CanRegisterFor`, `Library`,
`VarValues`) and are registered in
`pkg/evaluator/cel/evaluator.go` alongside the defaults. A minimal
plugin only needs a single `cel.ObjectType` for its namespace plus
one or more `cel.Function` registrations — see the `semver` package
for the smallest working example.
