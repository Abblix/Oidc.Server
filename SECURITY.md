# Security Policy

## Supported Versions

| Version     | Supported                                                                      |
|-------------|--------------------------------------------------------------------------------|
| Latest 2.x  | Yes: every security fix lands here                                             |
| Earlier 2.x | No fix in place. Upgrade to the latest 2.x, or ask us about a back-ported patch |
| 1.x         | No longer supported. Upgrade to 2.x                                            |

Full platform and end-of-support dates are on the
[version support lifecycle](https://docs.abblix.com/docs/version-support-lifecycle) page.

A fix is made in the latest release and reaches you by upgrading the package. The fixed package is published
on NuGet and available to everyone, including users of the free non-commercial licence: a security fix is
never gated behind a purchase.

Know what upgrading can cost, though. Minor releases in this library do carry breaking changes. In 2.4, for
instance, several endpoints become opt-in, and clients configured for pairwise subject identifiers see their
`sub` values change. Each release lists its breaking changes, and when we tell you which release carries your
fix, we will tell you what stands between your version and it.

Where upgrading is genuinely not an option, we can build a patch release for the specific 2.x version you run.
That is commercial work under your purchase agreement, not part of the standard licence, so write to
[info@abblix.com](mailto:info@abblix.com) and we will scope it. A version that has passed end of support
cannot be brought back into support by request.

## Scope

In scope: everything published from this repository. The `Abblix.OIDC.Server` package and its MVC and Minimal
API adapters, the `Abblix.JWT` packages including the Vault and Azure key providers, `Abblix.Oidc.Client`, and
the sample hosts.

We treat as a vulnerability a specification violation with a security consequence, an insecure default, a
control a host cannot configure correctly through the documented API, and any bypass of a check the library
claims to perform. A deployment that a host made insecure through its own configuration is not one, with an
important exception: if a dangerous configuration is reachable without a warning, or our documentation
recommends it, that is our defect and we will fix it.

Out of scope here: the services Abblix operates, and findings from a scanner with no demonstrated exploit
path. For the former, see Safe Harbor below.

## Reporting a Vulnerability

If you discover a security vulnerability in Abblix OIDC Server, please report it privately.

**Do NOT:**
- Open a public GitHub issue
- Discuss the vulnerability in GitHub Discussions or any public forum
- Publish details while we are working on a fix

**Preferred:
[report it privately on GitHub](https://github.com/Abblix/Oidc.Server/security/advisories/new).** That opens a
private thread with the maintainers, carries attachments, and does not travel as plain email.

**By email:** [support@abblix.com](mailto:support@abblix.com), with `SECURITY` in the subject so the report is
not queued behind support requests. If you have proof-of-concept code and would rather not send it by plain
email, say so and we will arrange a private channel.

Whichever route you take, tell us:
- The version you are on, and whether you can upgrade
- A description of the vulnerability and its potential impact
- Steps to reproduce: environment, configuration, request sequence
- Any proof-of-concept code, if available

## Our Response

- **Acknowledgement:** a maintainer replies within two business days, Astana time (UTC+5). A person, not an
  autoresponder. If five business days pass in silence, assume the message was lost rather than ignored, and
  write to [info@abblix.com](mailto:info@abblix.com).
- **Triage:** within five business days we tell you whether we reproduced it, how we rate it with CVSS v3.1,
  and whether we consider it a defect in this library or a deployment issue.
- **If we disagree:** tell us, and you will get a technical answer in the same thread from the person who made
  the call. Disagreement does not affect anything promised under Safe Harbor below, and it does not affect
  your right to publish on the timeline below.
- **Fix:** we aim to ship within 90 days and name a target date at triage. If it slips, you hear that from us
  before the date, while it still helps you.
- **Disclosure:** we agree a date with you and credit you by name unless you ask us not to. If 90 days pass
  from your report without a fix, or we cannot agree a date, you are free to publish, and doing so costs you
  nothing under this policy.

These timings cover the handling of vulnerability reports, from anyone, licence or no licence: a defect in
this library is our problem before it is yours. They are not technical support. Support and maintenance are
governed by your licence and purchase agreement, and Section 3.7 of the [licence](LICENSE.md) is explicit that
free non-commercial use carries no commitment to either.

We do not run a paid bug bounty.

## Safe Harbor

This section is incorporated by reference into the Abblix License Agreement under its Section 11.4(c), and it
binds Abblix LLP. Within its scope we will not bring or support legal action against you, and we will not
treat your research as a breach of the licence.

For good-faith security research under this policy, and notwithstanding Sections 2.2(a) and 2.2(b) of the
[licence](LICENSE.md), you may modify, instrument, decompile and fuzz the Software on an installation you
control. Nothing else in those sections is waived. What we ask in return:

- **Test against an installation you control.** Providers built on this library are deployed and operated by
  their owners, and their end users' accounts, tokens and data are not yours to reach. Probing a live provider
  you do not run is that operator's security incident rather than research on this library, and this policy
  does not cover it. That includes the services Abblix operates, among them Abblix Account and the public
  demo: to test one of ours, write to us first and we will tell you what is in scope.
- **Take no more data than proving the issue requires.** A working reproduction is what we need; anything
  gathered past that point is not part of it.
- **Give us time before you publish**, on the terms under Our Response above.

## Security Updates

Releases carrying security fixes are published on
[GitHub Releases](https://github.com/Abblix/Oidc.Server/releases) and on NuGet.

Where a fix needs nothing from you beyond upgrading, it ships inside an ordinary release. Where it requires
you to change configuration or code, we publish a
[GitHub Security Advisory](https://github.com/Abblix/Oidc.Server/security/advisories) naming the affected and
fixed versions, so that it reaches the GitHub Advisory Database and your build sees it through NuGet Audit and
`dotnet list package --vulnerable`. Either way, we tell the reporter which release carries the fix.

To follow along, watch this repository with Custom notifications and select Security alerts.

## Contact

- **Security reports:** [support@abblix.com](mailto:support@abblix.com), or
  [privately on GitHub](https://github.com/Abblix/Oidc.Server/security/advisories/new)
- **General inquiries:** [info@abblix.com](mailto:info@abblix.com)
