# `semver` CEL plugin

Exposes a `semver` object inside every CEL tenet so policies can
parse and compare [Semantic Versioning 2.0.0](https://semver.org/)
strings without resorting to regex tricks.

Implementation lives in this package; the plugin is registered as a
default in `pkg/evaluator/cel/evaluator.go`.

## Methods

| Expression                                  | Returns  | Description                                                      |
|:--------------------------------------------|:---------|:-----------------------------------------------------------------|
| `semver.major("1.2.3")`                     | `int`    | The major component.                                             |
| `semver.minor("1.2.3")`                     | `int`    | The minor component.                                             |
| `semver.patch("1.2.3")`                     | `int`    | The patch component.                                             |
| `semver.prerelease("1.2.3-alpha.1")`        | `string` | The pre-release label, or `""` if none.                          |
| `semver.build("1.2.3+sha.abc")`             | `string` | The build metadata, or `""` if none.                             |
| `semver.parse("1.2.3-alpha+sha")`           | `map`    | All components plus `original`, as a map.                        |
| `semver.isValid("1.2.3")`                   | `bool`   | True if the argument parses as a semver.                         |
| `semver.isStable("1.2.3")`                  | `bool`   | True when `major >= 1` and there is no pre-release tag.          |
| `semver.compare(a, b)`                      | `int`    | `-1` if `a < b`, `0` if equal, `1` if `a > b`.                   |
| `semver.isNewer(a, b)`                      | `bool`   | Shorthand for `compare(a, b) > 0`.                               |
| `semver.isOlder(a, b)`                      | `bool`   | Shorthand for `compare(a, b) < 0`.                               |
| `semver.equal(a, b)`                        | `bool`   | Shorthand for `compare(a, b) == 0`.                              |
| `semver.satisfies(v, constraint)`           | `bool`   | Evaluates a [Masterminds/semver constraint](https://github.com/Masterminds/semver#checking-version-constraints) (`^1.2.3`, `>=1.0.0 <2.0.0`, `~1.2`, …). |

### Types

`major`, `minor`, and `patch` return `int` so callers can do
arithmetic directly. Wrap with CEL's `string()` constructor when a
string is needed:

```cel
string(semver.major(subject.name))  // -> "1"
```

### Leading `v`

Version strings with a leading `v` (e.g. `"v1.2.3"`) are accepted
and produce the same result as the un-prefixed form.

### Validation

Unparseable inputs return a CEL evaluation error. When you need to
guard an expression, reach for `semver.isValid` first:

```cel
semver.isValid(subject.name) && semver.major(subject.name) >= 2
```

## Recipes

Reject artefacts below a baseline:

```cel
semver.satisfies(predicate.data.version, ">=2.0.0 <3.0.0")
```

Block pre-release builds from promoting to production:

```cel
semver.isStable(predicate.data.version)
```

Only allow patch bumps compared to a pinned base:

```cel
semver.major(predicate.data.version) == semver.major(context.base) &&
semver.minor(predicate.data.version) == semver.minor(context.base) &&
!semver.isOlder(predicate.data.version, context.base)
```
