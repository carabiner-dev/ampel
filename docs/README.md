# 🔴🟡🟢 AMPEL

### The Amazing Multipurpose Policy Engine (and L)

Version: 1.0-pre<br>
Copyright © 2025 Carbiner Systems, Inc

## An Introduction to the AMPEL Policy Engine

AMPEL is a policy engine specially crafted to protect the software development
lifecycle through trusted security metadata. It has native support for Software
Supply Chain Security technologies such as In-toto, Sigstore, SLSA, Protobom, etc
but it can also work with any kind of signed metadata.

The engine is extensible in various ways, from pluggable evaluation runtimes to
transformers and runtime plugins. It is designed to be embedable in software
powering software builds, packaging and delivery.

AMPEL is a backronym in search of a meaning. It currently stands for Amazing
Multipurpose Policy Engine (and L), so we are 80% there!

This is the AMPEL user manual. We do our best to keep these docs up to date,
but - as all software documentation - expect the manual to be always under
construction and always behind the latest version. As always, patches and
contributions are welcome!

## Table of Contents

- Policy Evaluation Basics
  - Three Main Ingredients
  - Basic Evaluation Run

- The AMPEL Attestation Framework
  - How AMPEL Abstracts Attestations
    - Wrappers
      - Signed Envelopes
      - The "Bare" Envelope
    - Contents
      - Subjects
      - Statements
      - Predicates
  - Reading Attestations
    - Types and Versioning
    - Queries and Filters
    - Collectors
  - Signatures and Identities
  - Tools
    - bnd

- The AMPEL Policy Guide
  - Policies and PolicySets
  - A Word About Runtimes
  - The Main Policy Structure
    - Metadata
    - Identities
    - Predicate Spec
    - Tenets
  - Context
  - Transformers
  - Attestation Chaining
  - Identities
    - Identity Types
    - Sigstore Identities
    - Keys
  - Outputs
  - Security Frameworks
    - Tying Policies to Controls

- Working With PolicySets
  - Abstracting Common Properties
    - Identities
    - Contexts
  - PolicySets and Security Frameworks

- Remote Policies and References
  - How Referencing Works
  - Overriding Policy Definitions
  - Abstracting Common Overrides
  - Sources
    - HTTP
    - git

- Evaluation Results
  - Evaluation Status
  - Results Objects
    - Evaluation Result
    - ResultSet
  - Attesting Results
  - Displaying Results
    - Display Drivers

- Appendix A: The AMPEL CEL Runtime
  - The Runtime Environment
  - AMPEL Functions
  - Plugins
