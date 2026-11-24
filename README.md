<a name="top"></a>
[![Abblix OIDC Server](https://resources.abblix.com/imgs/jpg/abblix-oidc-server-github-banner.jpg)](https://www.abblix.com/en/oidc-server)
[![.NET](https://img.shields.io/badge/.NET-11.0-512BD4)](https://www.abblix.com/en/docs/technical-requirements)
[![language](https://img.shields.io/badge/language-C%23-239120)](https://learn.microsoft.com/en-us/dotnet/csharp/tour-of-csharp/overview)
[![OS](https://img.shields.io/badge/OS-linux%2C%20windows%2C%20macOS-0078D4)](https://www.abblix.com/en/docs/technical-requirements)
[![CPU](https://img.shields.io/badge/CPU-x86%2C%20x64%2C%20ARM%2C%20ARM64-FF8C00)](https://www.abblix.com/en/docs/technical-requirements)
[![security rating](https://sonarcloud.io/api/project_badges/measure?project=Abblix_Oidc.Server&metric=security_rating)](https://sonarcloud.io/summary/overall?id=Abblix_Oidc.Server)
[![reliability rating](https://sonarcloud.io/api/project_badges/measure?project=Abblix_Oidc.Server&metric=reliability_rating)](https://sonarcloud.io/summary/overall?id=Abblix_Oidc.Server)
[![maintainability rating](https://sonarcloud.io/api/project_badges/measure?project=Abblix_Oidc.Server&metric=sqale_rating)](https://sonarcloud.io/summary/overall?id=Abblix_Oidc.Server)
[![CodeQL analysis](https://github.com/Abblix/Oidc.Server/actions/workflows/codeql.yml/badge.svg?branch=develop)](https://github.com/Abblix/Oidc.Server/security/code-scanning?query=is%3Aopen)
[![NuGet Downloads](https://img.shields.io/nuget/dt/Abblix.OIDC.Server)](https://www.nuget.org/packages/Abblix.OIDC.Server)
[![GitHub release](https://img.shields.io/github/v/release/Abblix/Oidc.Server)](#)
[![GitHub release date](https://img.shields.io/github/release-date/Abblix/Oidc.Server)](#)
[![GitHub last commit](https://img.shields.io/github/last-commit/Abblix/Oidc.Server)](#)
[![getting started](https://img.shields.io/badge/getting_started-guide-1D76DB)](https://www.abblix.com/en/docs/getting-started-guide)
[![migrating from IdentityServer](https://img.shields.io/badge/migrating_from_IdentityServer-guide-1D76DB)](https://www.abblix.com/en/docs/migrate-from-identityserver)
[![License](https://img.shields.io/badge/license-Source_Available-blue)](LICENSE.md)
[![Free](https://img.shields.io/badge/free_under_%241M_revenue-brightgreen)](#-license)

⭐ Star us on GitHub: your support motivates us a lot! 🙏😊

[![Share](https://img.shields.io/badge/share-000000?logo=x&logoColor=white)](https://x.com/intent/tweet?text=Check%20out%20this%20project%20on%20GitHub:%20https://github.com/Abblix/Oidc.Server%20%23OpenIDConnect%20%23Security%20%23Authentication)
[![Share](https://img.shields.io/badge/share-1877F2?logo=facebook&logoColor=white)](https://www.facebook.com/sharer/sharer.php?u=https://github.com/Abblix/Oidc.Server)
[![Share](https://img.shields.io/badge/share-0A66C2?logo=linkedin&logoColor=white)](https://www.linkedin.com/sharing/share-offsite/?url=https://github.com/Abblix/Oidc.Server)
[![Share](https://img.shields.io/badge/share-FF4500?logo=reddit&logoColor=white)](https://www.reddit.com/submit?title=Check%20out%20this%20project%20on%20GitHub:%20https://github.com/Abblix/Oidc.Server)
[![Share](https://img.shields.io/badge/share-0088CC?logo=telegram&logoColor=white)](https://t.me/share/url?url=https://github.com/Abblix/Oidc.Server&text=Check%20out%20this%20project%20on%20GitHub)

Add an OpenID Connect provider to your own ASP.NET Core app. It runs inside your app rather than as a separate server to deploy and operate.

📑 For the full picture, see the [technical overview](https://resources.abblix.com/pdf/abblix-oidc-server-presentation-eng.pdf).

## Table of Contents
- [About](#-about)
- [Quickstart](#-quickstart)
- [Packages](#-packages)
- [Certification](#-certification)
- [Upgrading](#%EF%B8%8F-upgrading)
- [Documentation](#-documentation)
- [Abblix Account](#-abblix-account)
- [Feedback](#-feedback)
- [License](#-license)
- [Contacts](#%EF%B8%8F-contacts)

## 🚀 About

Abblix OIDC Server turns your ASP.NET Core application into an OpenID Connect provider. Rather than deploying and operating a separate identity server, you embed the protocol directly into your app, so your users, your data, and your UI stay inside your product.

- A library inside your app, not a server you run: the OpenID Connect endpoints run in your process, so users, data, and UI never leave it.
- Current with the modern security stack: DPoP, PAR, JARM, RAR, CIBA, device authorization, token exchange, certificate-bound tokens and JWT introspection responses, alongside the OAuth 2.0 and OpenID Connect core.
- Security profiles the server enforces per client or per tenant, not certified: FAPI 2.0, FAPI 2.0 Message Signing and FAPI 1.0 Advanced, which also holds CIBA clients to FAPI-CIBA. Every 3.x release runs their OpenID Foundation conformance plans.
- Many issuers in one deployment: each tenant has its own clients, keys and security profile, declared at startup or added while the server runs. The free tier allows one production issuer, see [License](#-license).
- Engineering you can audit: a large automated test suite, top SonarCloud security, reliability, and maintainability ratings, and a CodeQL scan of every push to the development branch.
- Modern .NET, minimal friction: requires .NET 11 and the .NET 11 SDK, with drop-in adapters for both MVC and Minimal API. A host on .NET 8, 9 or 10 uses 2.x, which still receives security fixes (see the [Security Policy](SECURITY.md)).
- Observable through OpenTelemetry: each endpoint request gets its own span and metrics, and the structured logs the server writes carry the trace of the request they belong to.

Under the hood, the library leans on modular and hexagonal architecture and the standard .NET DI container, which keeps it testable and easy to extend. It ships two ASP.NET Core integration adapters that expose the same OpenID Connect endpoints (one for MVC controllers and routing, one for Minimal API endpoint routing), so you adopt whichever hosting model your application already uses, without taking a dependency on the other.

## ⚡ Quickstart

You need the .NET 11 SDK. Install the Minimal API adapter, then register the server and map its endpoints in `Program.cs`:

```shell
dotnet add package Abblix.OIDC.Server.MinimalAPI
```

```csharp
using Abblix.Jwt;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.MinimalApi;

var builder = WebApplication.CreateBuilder(args);

// Grants every client everything it asks for, which suits only clients of your own;
// to ask the end user for consent, register your own IUserConsentsProvider instead
builder.Services.AddConsentGrantedForEveryClient();

// Turn your ASP.NET Core app into an OpenID Connect provider serving one issuer
builder.Services.AddOidcServices(options => options.Tenants.Add(new TenantDefinition
{
    Id = "main",
    // The address the app is served on, written into every token it issues.
    // Set it as "Issuer" in appsettings.json or any other configuration source
    Issuer = new Uri(builder.Configuration["Issuer"]
        ?? throw new InvalidOperationException("Set Issuer to the address the app is served on")),
    LoginUri = new Uri("/Auth/Login", UriKind.Relative),
    SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
}));

var app = builder.Build();

app.UseCors();
app.MapOidcEndpoints();
app.Run();
```

The issuer comes from configuration, so add it to `appsettings.json` first, for example `"Issuer": "https://localhost:5001"`.

An MVC application installs `Abblix.OIDC.Server.MVC` and calls `app.MapOidcControllers()` instead. Some hosts also call `app.UseMultiTenancy()`; [Upgrading to 3.0](https://www.abblix.com/en/docs/upgrading-to-3.0) says which.

This is the outline, not a complete application: it serves discovery and the signing keys, and it issues a token once it has a client, a login page and your user store. The [Getting Started Guide](https://www.abblix.com/en/docs/getting-started-guide) builds a complete, runnable solution, with caches and keys for several instances.

## 📦 Packages

The quickstart uses the Minimal API adapter; an MVC application installs `Abblix.OIDC.Server.MVC`. Both adapters expose the same OpenID Connect endpoints and pull in the core `Abblix.OIDC.Server` package as a dependency, so pick the one that matches how your application maps requests. For hosts that wire the protocol layer directly, install `Abblix.OIDC.Server` instead.

[Abblix.OIDC](src/Abblix.Oidc/README.md) (the OAuth 2.0 and OpenID Connect vocabulary the server shares with its clients), [Abblix.JWT](src/Abblix.Jwt/README.md) (JWT signing, encryption and validation on the platform's own cryptography), [Abblix.SecurityEvents](src/Abblix.SecurityEvents/README.md) (Security Event Tokens) and [Abblix.DependencyInjection](src/Abblix.DependencyInjection/README.md) (the registration patterns the server is built on) come with the server. The rest are optional: add each one only if you actually need its feature.

|Package|What it adds|
|:-|:-|
|[Abblix.JWT.Vault](src/Abblix.Jwt.Vault/README.md), [Abblix.JWT.Azure](src/Abblix.Jwt.Azure/README.md)|Signing and decryption keys held in, or sealed by, HashiCorp Vault or OpenBao Transit, or Azure Key Vault (see [External key custodians](EXTERNAL_KEYS.md))|
|[Abblix.OIDC.Server.SharedSignals](src/Abblix.Oidc.Server.SharedSignals/README.md)|A Shared Signals transmitter for each tenant of the server|
|[Abblix.SharedSignals](src/Abblix.SharedSignals/README.md), [.MinimalAPI](src/Abblix.SharedSignals.MinimalApi/README.md), [.Redis](src/Abblix.SharedSignals.Redis/README.md)|OpenID Shared Signals Framework 1.0 transmitter and receiver, its endpoints, and a Redis event outbox for several replicas|
|[Abblix.SecurityEvents.CAEP](src/Abblix.SecurityEvents.CAEP/README.md), [.RISC](src/Abblix.SecurityEvents.RISC/README.md), [.MinimalAPI](src/Abblix.SecurityEvents.MinimalApi/README.md)|The CAEP and RISC security event types, and endpoints receiving security events|

## 🎓 Certification

[![OpenID Foundation Certification](https://resources.abblix.com/imgs/svg/abblix-oidc-server-openid-foundation-certification-mark.svg)](https://oidc.abblix.com/certified-profiles)

Versions 1.x and 2.x are certified by the OpenID Foundation in every OpenID Connect provider profile and every logout profile, and 3.x is being prepared for certification; every 3.x release runs the same conformance plans. The [certified profiles](https://oidc.abblix.com/certified-profiles) page links each official test result.

## ⬆️ Upgrading

Each release that asks something of a host has a guide that lists what changes and how:

- [Upgrading to 3.1](https://www.abblix.com/en/docs/upgrading-to-3.1) from 3.0
- [Upgrading to 3.0](https://www.abblix.com/en/docs/upgrading-to-3.0) from 2.x

## 📚 Documentation

### Getting Started
The [Getting Started Guide](https://www.abblix.com/en/docs/getting-started-guide) builds a working OpenID Connect provider on ASP.NET MVC step by step.

### Migrating from IdentityServer
[Migrating from IdentityServer4 or Duende](https://www.abblix.com/en/docs/migrate-from-identityserver) walks through a real migration end to end: dotnet/eShop's Identity.API moved from Duende IdentityServer onto Abblix OIDC Server, every decision named along the way.

### Shared Signals
[A working Shared Signals transmitter and receiver for ASP.NET Core](https://www.abblix.com/en/docs/shared-signals-guide) shows two hosts exchanging a signed Security Event Token over HTTPS, each verifying the other.

The [Documentation](https://www.abblix.com/en/docs/introduction-to-abblix-oidc-server) site covers configuration, deployment, the API reference and the OpenID Connect standard itself.

## 💎 Abblix Account

Prefer not to run the provider yourself? [Abblix Account](https://account.abblix.com) is a ready-to-use cloud service built on this library, with passkeys, MFA and social login; [Quorvel Coffee](https://quorvel.abblix.com) shows it at work.

## 🤝 Feedback

Report what you run into, with the flow and the client you used, in [issues](https://github.com/Abblix/Oidc.Server/issues) or the [discussions](https://github.com/Abblix/Oidc.Server/discussions).

## 📃 License

This product is distributed under a source-available proprietary license.

It is free of charge for companies under $1M in annual revenue and under $1M raised in outside funding, for
non-profits, educational institutions, personal projects and non-commercial open source. Free use allows one
production issuer, with every protocol included and no limit on client applications or users. It comes "as is",
with no guaranteed response time and no commitment to updates or maintenance.

See 📋[License Agreement](LICENSE.md) for details.

Redistributing the library to third parties inside a product you sell or deploy at customer sites needs a separate
redistribution license. License types and prices are on the [pricing page](https://www.abblix.com/en/oidc-server/pricing).

## 🗨️ Contacts

For more details about our products, services, or any general information regarding the Abblix OIDC Server, feel free to reach out to us. Below are the best ways to contact our team:

- General inquiries: [info@abblix.com](mailto:info@abblix.com)
- Support and security reports: [support@abblix.com](mailto:support@abblix.com), see the [Security Policy](SECURITY.md)
- Website: [Abblix OIDC Server](https://www.abblix.com/en/oidc-server)

Subscribe to our LinkedIn and Twitter:

[![LinkedIn](https://img.shields.io/badge/subscribe-white.svg?logo=data:image/svg%2bxml;base64,PHN2ZyB2aWV3Qm94PSIwIDAgMjQgMjQiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHBhdGggZD0iTTIwLjQ0NyAyMC40NTJoLTMuNTU0di01LjU2OWMwLTEuMzI4LS4wMjctMy4wMzctMS44NTItMy4wMzctMS44NTMgMC0yLjEzNiAxLjQ0NS0yLjEzNiAyLjkzOXY1LjY2N0g5LjM1MVY5aDMuNDE0djEuNTYxaC4wNDZjLjQ3Ny0uOSAxLjYzNy0xLjg1IDMuMzctMS44NSAzLjYwMSAwIDQuMjY3IDIuMzcgNC4yNjcgNS40NTV2Ni4yODZ6TTUuMzM3IDcuNDMzYTIuMDYyIDIuMDYyIDAgMCAxLTIuMDYzLTIuMDY1IDIuMDY0IDIuMDY0IDAgMSAxIDIuMDYzIDIuMDY1em0xLjc4MiAxMy4wMTlIMy41NTVWOWgzLjU2NHYxMS40NTJ6TTIyLjIyNSAwSDEuNzcxQy43OTIgMCAwIC43NzQgMCAxLjcyOXYyMC41NDJDMCAyMy4yMjcuNzkyIDI0IDEuNzcxIDI0aDIwLjQ1MUMyMy4yIDI0IDI0IDIzLjIyNyAyNCAyMi4yNzFWMS43MjlDMjQgLjc3NCAyMy4yIDAgMjIuMjIyIDBoLjAwM3oiIGZpbGw9IiMwQTY2QzIiLz48cGF0aCBzdHlsZT0iZmlsbDojZmZmO3N0cm9rZS13aWR0aDouMDIwOTI0MSIgZD0iTTQuOTE3IDcuMzc3YTIuMDUyIDIuMDUyIDAgMCAxLS4yNC0zLjk0OWMxLjEyNS0uMzg0IDIuMzM5LjI3NCAyLjY1IDEuNDM3LjA2OC4yNS4wNjguNzY3LjAwMSAxLjAxYTIuMDg5IDIuMDg5IDAgMCAxLTEuNjIgMS41MSAyLjMzNCAyLjMzNCAwIDAgMS0uNzktLjAwOHoiLz48cGF0aCBzdHlsZT0iZmlsbDojZmZmO3N0cm9rZS13aWR0aDouMDIwOTI0MSIgZD0iTTQuOTE3IDcuMzc3YTIuMDU2IDIuMDU2IDAgMCAxLTEuNTItMi42NyAyLjA0NyAyLjA0NyAwIDAgMSAzLjQxOS0uNzU2Yy4yNC4yNTQuNDIuNTczLjUxMi45MDguMDY1LjI0LjA2NS43OCAwIDEuMDItLjA1MS4xODYtLjE5Ny41MDQtLjMuNjUyLS4wOS4xMzItLjMxLjM2Mi0uNDQzLjQ2NC0uNDYzLjM1Ny0xLjEuNTAzLTEuNjY4LjM4MlpNMy41NTcgMTQuNzJWOS4wMDhoMy41NTd2MTEuNDI0SDMuNTU3Wk05LjM1MyAxNC43MlY5LjAwOGgzLjQxMXYuNzg1YzAgLjYxNC4wMDUuNzg0LjAyNi43ODMuMDE0IDAgLjA3LS4wNzMuMTI0LS4xNjIuNTI0LS44NjUgMS41MDgtMS40NzggMi42NS0xLjY1LjI3NS0uMDQyIDEtLjA0NyAxLjMzMi0uMDA5Ljc5LjA5IDEuNDUxLjMxNiAxLjk0LjY2NC4yMi4xNTcuNTU3LjQ5My43MTQuNzEzLjQyLjU5Mi42OSAxLjQxMi44MDggMi40NjQuMDc0LjY2My4wODQgMS4yMTUuMDg1IDQuNTc4djMuMjU4aC0zLjUzNnYtMi45ODZjMC0yLjk3LS4wMS0zLjQ3NC0uMDc0LTMuOTA4LS4wOS0uNjA2LS4zMTQtMS4wODItLjYzNC0xLjM0Mi0uMzk1LS4zMjItMS4wMjktLjQzNy0xLjcwMy0uMzA5LS44NTguMTYzLTEuMzU1Ljc1LTEuNTIzIDEuNzk3LS4wNzYuNDcxLS4wODQuODQ1LS4wODQgMy44MzR2Mi45MTRIOS4zNTN6Ii8+PC9zdmc+)](https://www.linkedin.com/company/103540510/)
[![X](https://img.shields.io/badge/subscribe-white.svg?logo=data:image/svg%2bxml;base64,PHN2ZyB2aWV3Qm94PSIwIDAgMjQgMjQiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHBhdGggZD0iTTE4LjkwMSAxLjE1M2gzLjY4bC04LjA0IDkuMTlMMjQgMjIuODQ2aC03LjQwNmwtNS44LTcuNTg0LTYuNjM4IDcuNTg0SC40NzRsOC42LTkuODNMMCAxLjE1NGg3LjU5NGw1LjI0MyA2LjkzMlpNMTcuNjEgMjAuNjQ0aDIuMDM5TDYuNDg2IDMuMjRINC4yOThaIi8+PHBhdGggc3R5bGU9ImZpbGw6I2ZmZjtzdHJva2Utd2lkdGg6LjAyMDkyNDEiIGQ9Ik0xMS4wMzYgMTIuMDI4IDQuMzg3IDMuMzM0bC0uMDYtLjA4SDYuNDhsNi41MTYgOC42MTQgNi41NzUgOC42OTQuMDYuMDhoLTIuMDA2eiIvPjwvc3ZnPg==)](https://twitter.com/OIDCServer)

[Back to top](#top)
