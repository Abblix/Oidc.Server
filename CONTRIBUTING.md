# Contributing to Abblix OIDC Server

Thank you for your interest in Abblix OIDC Server. Bug reports, specification gaps and real integration scenarios from the people who build on this library go straight into what we fix and what we build next.

This note explains how the project is developed, so your effort goes where it counts.

## How the codebase is maintained

Abblix OIDC Server is a source-available commercial product, developed in-house by the Abblix team. We do not accept external pull requests, and outside code is not merged into the codebase. This lets us keep full ownership of the architecture, apply one consistent standard for security and specification conformance, and keep the provenance of every line clear under our [license](LICENSE.md).

That is not a judgement on the quality of outside work. It is how we keep a security-critical identity library coherent and accountable.

## How you can help

These are the contributions we value most:

- **Report a bug.** Open a [GitHub issue](https://github.com/Abblix/Oidc.Server/issues) with the library version, your .NET version, your configuration, the request sequence, and what you expected versus what happened. A clear reproduction is the fastest path to a fix.
- **Suggest a feature or improvement.** Open an [issue](https://github.com/Abblix/Oidc.Server/issues), or post in [Ideas](https://github.com/Abblix/Oidc.Server/discussions/categories/ideas) describing the use case. That is where we ask what to build next, and we read it when planning. We cannot build everything, and we say so when we decide against something.
- **Point out a specification gap.** If something diverges from an RFC or an OpenID Connect specification, tell us which clause, and where our behaviour departs from it. Abblix OIDC Server is certified by the OpenID Foundation, and the standards it implements are listed in the [documentation](https://docs.abblix.com/docs/implemented-standards): a divergence from a clause is a defect, and we treat it as one.
- **Ask a question.** [Q&A](https://github.com/Abblix/Oidc.Server/discussions/categories/q-a) is the place for integration questions and design conversations.

## Security issues

Anything that lets someone obtain a token, a session or a claim they should not have, or that weakens a check this library is meant to perform, goes to [support@abblix.com](mailto:support@abblix.com) or through [private reporting on GitHub](https://github.com/Abblix/Oidc.Server/security/advisories/new). Never to a public issue or discussion. The process is in [SECURITY.md](SECURITY.md).

If you are unsure which kind you are holding, treat it as a security issue. We would far rather receive an ordinary bug privately than read a live vulnerability in a public thread, and we will tell you when it is fine to move it into the open.

## Ideas you post here

Anything you post in issues or discussions we may implement freely and without obligation, and we claim nothing over what you keep to yourself. Please do not post code you want to retain rights in, or anything confidential to your employer: we will not merge it, and these are public forums.

## Contact

- Bugs and feature ideas: [GitHub Issues](https://github.com/Abblix/Oidc.Server/issues)
- Questions and discussion: [GitHub Discussions](https://github.com/Abblix/Oidc.Server/discussions)
- Security vulnerabilities: [support@abblix.com](mailto:support@abblix.com), see [SECURITY.md](SECURITY.md)
- Everything else: [info@abblix.com](mailto:info@abblix.com)

We triage new issues weekly and reply to every bug report. Thank you for the time you take to help us make Abblix OIDC Server better.
