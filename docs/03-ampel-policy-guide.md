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
