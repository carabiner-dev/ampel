# The AMPEL Policy Guide

This document provides a deep dive into AMPEL policies, their structure
and format. 

## Policies and PolicySets

Attested data captures claims about a piece of software. An AMPEL policy
codifies a set of expectations called _tenets_ that are expected to be
true for a policy to pass.

The policy _frame_ defines the environment and data a policy needs to run while
the policy _code_ in each tenet defines the rules to test the ingested predicate data.

Most scenarios where AMPEL runs require more than one policy as we may be
looking for different things in attestations or the required information may be
in more than one attestation. To makr things easier to manage, groups of
policies may be bound together in a `PolicySet`. A policy set provides a logical
container for related policies and AMPEL can gate processes on the combined
results, that is the passing status of the whole set.

## A Word About Runtimes

As disccussed previously, AMPEL sets up the policy environment and then, the
tenet code is executed in a runtime. AMPEL exposes some data in the runtime
execution environment that the policy code can use:

- Loaded Predicates
- Subject data
- Attestation signer identities
- Context data
- Any data and functions defined by runtime plugins

Runtimes are sepcified in the policy framework. While AMPEL supports swappable
runtimes, at the time of writing it only ships with the default CEL (Common
Expression Language) runtime. See appendix a for details and examples.

## General Policy Structure

An AMPEL policy can be extgremely simply but the structure is flexible enough to
support complex use cases. A simple but sufficiently secure policy should have
the following parts:

### Metadata

The metadata block contains information about the policy itself. It has fields like 
its description, expiration date, runtime, etc.

### Identities

While not reuired, a policy must specify the identities that can sign the
attestations selected for evaluation. While AMPEL verifies the signatures
automatically, the sigstore identities or the signer keys will be compared
against the identities list defined in the policy. If none match, the policy
will fail.

### Predicate Spec

(Required) A policy must specify at least one predicate type to run. Any matching
predicates will be loaded and exposed in the runtime environment.

Predicate types are versioned but a policy can specify an unversioned URI to match
any version of the same type. More than one predicate type can be specified, it
is up to the policy code to make sense of the loaded data.

### Tenets

A tenet is the logical unit of the policy. It wraps the policy code to add data
to specify human messages, the tenet ID and errors. Tenets can also specify a
subset of predicate types from the list defined at the policy level.

More importantly, Tenets specify _outputs_. Outputs are values pre-extracted from
the predicate data and exposed during at evaluation time. While not required,
outputs are useful when a policy needs to express in its evaluation results  the
data it looked at when evaluating. See the outputs section later in the handbook
for more information.

## Evaluation Context

In order to achieve the maximum level of reusability, policy behavior can be
tuned to changing environment conditions with contextual data. For example, a
policy can define a context value with the repository name, that would allow it
to define tenets that can evaluate in any repository.

### An Intro to Contextual Data

Contextual data is not meant to be used a general purpose variables, the idea
of contextual data is to anchor the policy better to the environment it is
running. Without contextual data, policies could break if reused in another
environment.

Contextual data should not be used to feed AMPEL properties about the subject
under evaluation or data that should be in a signed attestation. Instead,
contextual data should reflect data from the environment that changes when 
executing a tenet in another environment.

For example, lets say you have an SBOM with data about a Linux binary and a Darwin
binary. Instead of having one policy for mac and one for linux, you could define
a contextual `platform` value that reacts to the platform running the evaluation.
This way you can have a single policy that works anywhere.

### The ContextVal struct

When a policy needs contextual values, the JSON document lists them under the
top-level `context` key. The context block is a map of `ContextVal` objects
that define a value, a default and a flag marking it as required:

```json
    "context": {
        "username": {
            "value": "",
            "default": "User",
            "required": true
        }
    }
```

If required values are not defined, the evaluation will error before executing
any of its tenets. Values "burned" into the policy (defined in the policy JSON)
cannot be modified from the command line. They can be overriden when composing 
policies but in general they are immutable.

There is no type definition or a way to coerce the type of a value. When setting
or overriding a value, the new value can be of a different type. It is up to the
evaluation runtime to cast the context values into their preferred type
representation but in general if the  runtime is typed (such as CEL for example),
the runtime _should_ respect the original type.

### Common Context in PolicySets

PolicySets can define common contextual values. These values are defined in its
commons section and are exposed to all policies contained in the PolicySet.

```json
    "common": {
        "context": {
            "email": {
                "default": "hostmaster@example.com",
                "required": false
            },
            "num_reviewers": {
                "value": 2
            }
        }
    }
```

Policies can override the common context definition. If a policy defines a 
ContextVal under and existing key, the policy's values are merged with the
ancestor. This means that values re-defined at the policy level replace those
at the PolicySet level. Fields not present at the PolicySet level are added
if defined by the policy.

For example, in the example above, if a policy defines an `email`
entry with a value of `me@example.com`, and flipping the required value, the
resulting ContextVal would be:

```json
"email": {
    "default": "hostmaster@example.com",,
    "required": true,
    "value": "me@example.com"
}
```

As mentioned above, values can be replaced with another type for now.

### Data Sources

Contextual values can get their data from external sources which are not
connected to the subject, evidence or policy. In AMPEL's initial release we
support four sources: Policy code, a JSON struct, command line flags or
environment variables. AMPEL will support more ways of defining context
values in the future.

Data sources may define any number of values but note that for security 
purposes, any keys that are not defined in (or computed into) the policy
context definition will not be exposed to the evaluation engine.

#### Policy Code

Policy code can set the value of contextual data. As we saw, the context
definition can set a default value or set a value in its definition. Once
defined in the policy code a value cannot be changed unless it is overriden
from another value set in policy code.

Note that at if this writing, values trying to change a burned-in value are
simply ignored but at some point AMPEL may throw an error.

#### JSON Struct

For more control on types, conext values can be set using a JSON struct. This
struct can be passed inline through the command line or read from a file. The
JSON must be a map, keyed by stringsm with any value:

```json
{
    "name": "Yoda",
    "age": 999,
    "sith": false,
    "friends": ["Luke", "R2"]
}
```

To pass the data definitions in the command line simply pass the JSON in the
command line:

```
ampel verify ... --context-json='{"name":"Yoda","age":999,"sith":false,"friends":["Luke","R2"]}'
```

... or you can also put it in a file and read it by preceding the path with an @:

```
ampel verify ... --context-json @values.json
```

Values are parsed by the CLI, if the JSON data is invalid the verifier will not
run and return an error immediately.

#### Command Line Flag

`ampel verify` has a `--context` or `-x` flag that can be used to pass values
to populate the contextual entries. To define a value, put the key, a colon and
follow it with the value:

```
ampel verify ... --context="name:John Doe" -x "email:john@doe.com"
```

Note that all values defined with the `--context` flag are sent as string to 
the evaluation engine.

#### Environment Variables

Setting the `--context-env` flag loads the environent context provider. This
provider reads context data from environment variables. To expose context data
to AMPEL through envvars, set an environment variable with the `AMPEL_` prefix
followed by the context definition name in uppercase.

For example, to define this context value:

```json
  "context": {
    "email": { "required": true }
  }
```

Export an environment variable called `AMPEL_EMAIL`:

```bash
export AMPEL_EMAIL="joe@example.com"
```

Because of security constraints, all variable names need to have the prefix.
If you need to read an existing variable you could copy its value in the shell:

```bash
export AMPEL_USERNAME="${USERNAME}"
```

### Definition Override Order

When computing the stack of value definitions, the AMPEL CLI overrides the data
in the following order:

1. PolicySet Default
2. Policy Default
3. Environment Variable
4. JSON Struct
5. Command line flag
6. PolicySet value
7. Policy value

When referencing policies, a PolicySet or Policy derived from another
source file will inherit its parent's context definition and can override it.

Also note that this order applies to the ampel CLI verifier. Other programs
using AMPEL to verify may not follow this order.

### Using Context Data

Contextual data is exposed to the runtime and SHOULD be made available by the
runtime engine as a global value. As an example, a contextual value like this:

```json
{
    "context": {
        "spaceship":  {"default": "x-wing" }
    }
}
```

... can be accesed in the CEL runtime under the `context` global struct:

```cel
context.spaceship == "tie-fighter" // evaluates to false
```

#### Data types and Complex Data

As mentioned, values are untyped. Internally, AMPEL represents the context as
a `map[string]any` which means it can take virtually any value. But keep in 
mind that if you use complex funky data types, the runtime engine may not be
able to represent them and return an error. Therefore, it is recommende to
stick to basic types which can be represented in JSON.

### Context Values in Evaluation Results

To provide an explainable record of the policy run, AMPEL can output its
evaluation results as a Results attestation. Along with all other data used
during the evaluation, the computed data is captured into the policy results.
Note that the context definition, that is the PolicySet and Policy `ContextVal`s
are not captured, only the final compiled values. For example, this context
value:

```json
"context": {
    "pet": {
        "default": "Wicket W. Warrick",
        "value": "Chewbacca"
    }
}
```

... gets reflected in the evaluation results as:

```json
"context": {
    "pet": "Chewbacca"
}
```

Since context data is expected to change with the environment, the results
attestation keeps record of the computed values for future auditing.
