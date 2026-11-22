<a name="top"></a>
[![Abblix OIDC Server](https://resources.abblix.com/imgs/jpg/abblix-oidc-server-github-banner.jpg)](https://www.abblix.com/abblix-oidc-server)
[![.NET](https://img.shields.io/badge/.NET-11.0-512BD4)](https://www.abblix.com/en/docs/technical-requirements)
[![language](https://img.shields.io/badge/language-C%23-239120)](https://learn.microsoft.com/en-us/dotnet/csharp/tour-of-csharp/overview)
[![OS](https://img.shields.io/badge/OS-linux%2C%20windows%2C%20macOS-0078D4)](https://www.abblix.com/en/docs/technical-requirements)
[![CPU](https://img.shields.io/badge/CPU-x86%2C%20x64%2C%20ARM%2C%20ARM64-FF8C00)](https://www.abblix.com/en/docs/technical-requirements)
[![security rating](https://sonarcloud.io/api/project_badges/measure?project=Abblix_Oidc.Server&metric=security_rating)](https://sonarcloud.io/summary/overall?id=Abblix_Oidc.Server)
[![reliability rating](https://sonarcloud.io/api/project_badges/measure?project=Abblix_Oidc.Server&metric=reliability_rating)](https://sonarcloud.io/summary/overall?id=Abblix_Oidc.Server)
[![maintainability rating](https://sonarcloud.io/api/project_badges/measure?project=Abblix_Oidc.Server&metric=sqale_rating)](https://sonarcloud.io/summary/overall?id=Abblix_Oidc.Server)
[![CodeQL analysis](https://github.com/Abblix/Oidc.Server/actions/workflows/codeql.yml/badge.svg?branch=develop)](https://github.com/Abblix/Oidc.Server/security/code-scanning?query=is%3Aopen)
[![tests](https://img.shields.io/badge/tests-11000+%20passing-brightgreen)](https://github.com/Abblix/Oidc.Server/tree/develop/tests)
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

Add an OpenID Connect provider to your own ASP.NET Core app, one you embed and own end to end rather than a separate server to run and operate.

📑 For the full picture, see the [technical overview](https://resources.abblix.com/pdf/abblix-oidc-server-presentation-eng.pdf).

## Table of Contents
- [About](#-about)
- [Quickstart](#-quickstart)
- [Certification](#-certification)
- [How to Install](#-how-to-install)
- [Upgrading to 3.1](#%EF%B8%8F-upgrading-to-31)
- [Upgrading to 3.0](#%EF%B8%8F-upgrading-to-30)
- [Documentation](#-documentation)
- [Abblix Account](#-abblix-account)
- [Feedback and Contributions](#-feedback-and-contributions)
- [License](#-license)
- [Contacts](#%EF%B8%8F-contacts)

## 🚀 About

Abblix OIDC Server turns your ASP.NET Core application into an OpenID Connect provider. Rather than deploying and operating a separate identity server, you embed the protocol directly into your app, so your users, your data, and your UI stay inside your product.

- Certified in versions 1.x and 2.x: all seven OpenID Provider profiles and all four logout profiles; in the 2.x certification 634 conformance tests passed with none skipped and no warnings. Version 3.x is being prepared for certification and passes the same plans before every release. FAPI is not among the certified profiles.
- A library you own, not a server you run: the OpenID Connect endpoints live inside your app, so users, data, and UI never leave it.
- Current with the modern security stack: DPoP, PAR, JARM, RAR, CIBA, device authorization, token exchange, certificate-bound tokens and JWT introspection responses, alongside the OAuth 2.0 and OpenID Connect core.
- Security profiles the server enforces per client or per tenant, not certified: FAPI 2.0, FAPI 2.0 Message Signing and FAPI 1.0 Advanced, which also holds CIBA clients to FAPI-CIBA. Every 3.x release runs their OpenID Foundation conformance plans.
- The test suite of version 3.0 covers over 90% of the lines and branches of the hand-written code its packages ship.
- Many issuers in one deployment: each tenant has its own clients, keys and security profile, declared at startup or added while the server runs. The free tier allows one production issuer, see [License](#-license).
- Engineering you can audit: over 11,000 passing tests, top SonarCloud security, reliability, and maintainability ratings, and a CodeQL scan of every push to the development branch.
- Modern .NET, minimal friction: targets .NET 11, with drop-in adapters for both MVC and Minimal API.
- Observable through OpenTelemetry: each endpoint request gets its own span and metrics, and the structured logs the server writes carry the trace of the request they belong to.

Under the hood, the library leans on modular and hexagonal architecture and the standard .NET DI container, which keeps it testable and easy to extend. It ships two ASP.NET Core integration adapters that expose the same OpenID Connect endpoints (one for MVC controllers and routing, one for Minimal API endpoint routing), so you adopt whichever hosting model your application already uses, without taking a dependency on the other.

## ⚡ Quickstart

Install the Minimal API adapter, then register the server and map its endpoints in `Program.cs`:

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

An MVC application installs `Abblix.OIDC.Server.MVC` and calls `app.MapOidcControllers()` instead. A host serving several tenants, a single tenant at an issuer with a path, or tenants from a store or catalog of its own also calls `app.UseMultiTenancy()` before its own routing, so each request reaches its tenant.

This is the outline, not a complete application. The server keeps authorization codes, pushed requests and other short-lived state in an in-process cache unless you register an `IDistributedCache` of your own, which is enough for one instance; several instances need a shared one, such as Redis. The server finds a cache registered without a key, so a cache registered only as a keyed service has to be registered without one too. It also needs a login page, your user store, and signing keys that outlive a restart, since the key in the outline is generated anew at every start. The [Getting Started Guide](https://www.abblix.com/en/docs/getting-started-guide) builds a complete, runnable solution step by step.

## 🎓 Certification

[![OpenID Foundation Certification](https://resources.abblix.com/imgs/svg/abblix-oidc-server-openid-foundation-certification-mark.svg)](https://oidc.abblix.com/certified-profiles)

Versions 1.x and 2.x are certified in all seven OpenID Provider profiles and all four logout profiles. In the 2.x certification we skipped no tests and received no warnings: all 634 tests ![Passed](https://img.shields.io/badge/PASSED-brightgreen). For more details, click the links ([Certified OpenID Providers & Profiles](https://oidc.abblix.com/certified-profiles), [Certified OpenID Providers for Logout Profiles](https://oidc.abblix.com/certified-logout-profiles)).

Version 3.x is being prepared for certification. Until then, every 3.x release is held to the same suite: the release workflow runs the OpenID Foundation conformance plans for the certified OpenID Connect profiles and for FAPI 2.0, FAPI 2.0 Message Signing, FAPI 1.0 Advanced and FAPI-CIBA, and a release is not published unless they pass, apart from the few checks the suite cannot complete unattended, which the repository lists. The FAPI plans are run, not certified.

The tables below are the results of the 2.x certification:

### Regular Profiles
|OIDC Profile|Response Types (links to official OpenID Foundation test results)|Tests|
|:-|:-|:-|
|Basic OP|[code](https://www.certification.openid.net/plan-detail.html?public=true&plan=vaSiS5JvFcWr2)|36|
|Implicit OP|[id_token](https://www.certification.openid.net/plan-detail.html?public=true&plan=PHYWpi4iBLDmq)|58|
|Hybrid OP|[code id_token](https://www.certification.openid.net/plan-detail.html?public=true&plan=HPb7q9DYsfgcf)|102|
|Config OP|[config](https://www.certification.openid.net/plan-detail.html?public=true&plan=kcQTPdtyz1bt5)|1|
|Dynamic OP|[code](https://www.certification.openid.net/plan-detail.html?public=true&plan=Ie4igUuhKheHC) \| [code id_token](https://www.certification.openid.net/plan-detail.html?public=true&plan=wz8WwocsxeXLG) \| [code id_token token](https://www.certification.openid.net/plan-detail.html?public=true&plan=Vz0xyMMiabOuT) \| [code token](https://www.certification.openid.net/plan-detail.html?public=true&plan=di3sWIakE1NfO) \| [id_token](https://www.certification.openid.net/plan-detail.html?public=true&plan=siWnWnxc0F25Q) \| [id_token token](https://www.certification.openid.net/plan-detail.html?public=true&plan=sErNAjGZuRNMX)|127|
|Form Post OP|[basic](https://www.certification.openid.net/plan-detail.html?public=true&plan=2hkxl3otFUbdm) \| [implicit](https://www.certification.openid.net/plan-detail.html?public=true&plan=81Tzj22qYpFCy) \| [hybrid](https://www.certification.openid.net/plan-detail.html?public=true&plan=ywUWjGPWsyFuS)|196|
|3rd Party-Init OP|[code](https://www.certification.openid.net/plan-detail.html?public=true&plan=GB6nP470pDdVe) \| [code id_token](https://www.certification.openid.net/plan-detail.html?public=true&plan=M89emXc0N5GMF) \| [code id_token token](https://www.certification.openid.net/plan-detail.html?public=true&plan=pe5s8Gus3Uz3y) \| [code token](https://www.certification.openid.net/plan-detail.html?public=true&plan=JNX5OGMAKr2kr) \| [id_token](https://www.certification.openid.net/plan-detail.html?public=true&plan=gfI5xgx8UGzOL) \| [id_token token](https://www.certification.openid.net/plan-detail.html?public=true&plan=k4e0SJnvHGuu9)|12|
|Total||532|

### Logout Profiles

|OIDC Profile|Response Types (links to official OpenID Foundation test results)|Tests|
|:-|:-|:-|
|RP-Initiated OP|[code](https://www.certification.openid.net/plan-detail.html?public=true&plan=VPaBRT8VQQXhH) \| [code id_token](https://www.certification.openid.net/plan-detail.html?public=true&plan=WY5LQ9JYgTUdJ) \| [code id_token token](https://www.certification.openid.net/plan-detail.html?public=true&plan=nt4LY7vwN3ACO) \| [code token](https://www.certification.openid.net/plan-detail.html?public=true&plan=jLhRFKJXYJuEK) \| [id_token](https://www.certification.openid.net/plan-detail.html?public=true&plan=hwROnePvJvrXe) \| [id_token token](https://www.certification.openid.net/plan-detail.html?public=true&plan=3CVp7fx4TQX1H)|66|
|Session OP|[code](https://www.certification.openid.net/plan-detail.html?public=true&plan=N3Tsp7nigWMiS) \| [code id_token](https://www.certification.openid.net/plan-detail.html?public=true&plan=KqBqsHxH4vN03) \| [code id_token token](https://www.certification.openid.net/plan-detail.html?public=true&plan=KCwP7JqmXbcPf) \| [code token](https://www.certification.openid.net/plan-detail.html?public=true&plan=MJxcSnziJTOaa) \| [id_token](https://www.certification.openid.net/plan-detail.html?public=true&plan=9sZ9qkcq8VY1O) \| [id_token token](https://www.certification.openid.net/plan-detail.html?public=true&plan=OrRc3cBBm53OK)|12|
|Front-Channel OP|[code](https://www.certification.openid.net/plan-detail.html?public=true&plan=FCIMtfChd8JUR) \| [code id_token](https://www.certification.openid.net/plan-detail.html?public=true&plan=UPqVQppkBai8Q) \| [code id_token token](https://www.certification.openid.net/plan-detail.html?public=true&plan=TK2z4lTRgeU0O) \| [code token](https://www.certification.openid.net/plan-detail.html?public=true&plan=ntjIMSdbzeBJN) \| [id_token](https://www.certification.openid.net/plan-detail.html?public=true&plan=0SfPTdERrzANP) \| [id_token token](https://www.certification.openid.net/plan-detail.html?public=true&plan=RLQm9h40E4j1k)|12|
|Back-Channel OP|[code](https://www.certification.openid.net/plan-detail.html?public=true&plan=5kbQfVOWmJV76) \| [code id_token](https://www.certification.openid.net/plan-detail.html?public=true&plan=VWmk225h0coIZ) \| [code id_token token](https://www.certification.openid.net/plan-detail.html?public=true&plan=YzDOT2LFWi4X7) \| [code token](https://www.certification.openid.net/plan-detail.html?public=true&plan=RxPPCdLI7LlcR) \| [id_token](https://www.certification.openid.net/plan-detail.html?public=true&plan=x73qpcrHcFWv0) \| [id_token token](https://www.certification.openid.net/plan-detail.html?public=true&plan=uYoYs5BFAZkgr)|12|
|Total||102|

## 📦 How to Install

Add the adapter that matches your ASP.NET Core hosting model from NuGet.

For MVC controllers and routing:

```shell
dotnet add package Abblix.OIDC.Server.MVC
```

For Minimal API endpoint routing:

```shell
dotnet add package Abblix.OIDC.Server.MinimalAPI
```

Both adapters expose the same OpenID Connect endpoints and pull in the core `Abblix.OIDC.Server` package as a dependency, so pick the one that matches how your application maps requests. For hosts that wire the protocol layer directly, install `Abblix.OIDC.Server` instead.

[Abblix.OIDC](src/Abblix.Oidc/README.md) (the OAuth 2.0 and OpenID Connect vocabulary the server shares with its clients), [Abblix.JWT](src/Abblix.Jwt/README.md) (JWT signing, encryption and validation on the platform's own cryptography) [Abblix.SecurityEvents](src/Abblix.SecurityEvents/README.md) (Security Event Tokens) and [Abblix.DependencyInjection](src/Abblix.DependencyInjection/README.md) (the registration patterns the server is built on) come with the server. The rest are optional: add each one only if you actually need its feature.

|Package|What it adds|
|:-|:-|
|[Abblix.JWT.Vault](src/Abblix.Jwt.Vault/README.md), [Abblix.JWT.Azure](src/Abblix.Jwt.Azure/README.md)|Signing and decryption keys held in, or sealed by, HashiCorp Vault or OpenBao Transit, or Azure Key Vault (see [External key custodians](EXTERNAL_KEYS.md))|
|[Abblix.OIDC.Server.SharedSignals](src/Abblix.Oidc.Server.SharedSignals/README.md)|A Shared Signals transmitter for each tenant of the server|
|[Abblix.SharedSignals](src/Abblix.SharedSignals/README.md), [.MinimalAPI](src/Abblix.SharedSignals.MinimalApi/README.md), [.Redis](src/Abblix.SharedSignals.Redis/README.md)|OpenID Shared Signals Framework 1.0 transmitter and receiver, its endpoints, and a Redis event outbox for several replicas|
|[Abblix.SecurityEvents.CAEP](src/Abblix.SecurityEvents.CAEP/README.md), [.RISC](src/Abblix.SecurityEvents.RISC/README.md), [.MinimalAPI](src/Abblix.SecurityEvents.MinimalApi/README.md)|The CAEP and RISC security event types, and endpoints receiving security events|

## ⚠️ Upgrading to 3.1

Version 3.1 keeps the public API of 3.0 except three types of token exchange, `SubjectTokenContext`, `TokenExchangeGrantHandler` and `RefreshTokenSubjectTokenResolver` (below), so most hosts move by raising the package version. What a host checks before it does:

- Discovery publishes every endpoint on the scheme, host and port of the tenant's `Issuer`, whatever host the document was fetched by, and the register, read and update responses of RFC 7592 return `registration_client_uri` the same way. A consumer inside the deployment that fetches discovery by an internal name (a Docker Compose service, a cluster service name) reads the issuer's public addresses: it fetches discovery at the issuer, or names its endpoints itself.
- A signed request object (authorization, pushed authorization and backchannel authentication endpoints) and a CIBA `login_hint_token` that carry an `aud` must name the issuer identifier exactly as `TenantDefinition.Issuer` writes it. An `aud` naming only the endpoint address is refused. An object without `aud` is accepted.
- The JWT bearer grant accepts an `aud` naming the issuer identifier, the token endpoint on the issuer's scheme, host and port, or its mutual TLS alias where the tenant has one. `JwtBearerOptions.StrictAudienceValidation` is `[Obsolete]` and changes nothing: delete the line that assigns it, since under `TreatWarningsAsErrors` it fails the build with CS0618. Every audience refusal of the grant is logged under event id 2014, whose message carries the accepted token endpoint spellings as a list and no `{ApplicationUri}`; event id 2015 is not logged, so an alert keyed on it moves to 2014. A host constructing `JwtBearerAssertionPolicy` itself with the six-parameter constructor accepts only the issuer identifier; the constructor taking an `IServiceProvider` accepts the token endpoint too.
- A native client (`ApplicationType` `native`) and a public client (`TokenEndpointAuthMethod` `none`) use PKCE whatever `ClientInfo.PkceRequired` says: `ClientInfo.EffectivePkceRequired` is true for them, so the authorization endpoint refuses their code request without a `code_challenge`, clients in the host's own store included. Registration refuses `pkce_required: false` for such a client. A confidential web client keeps the opt-out.
- A native client declared in the tenant settings starts only with `TokenEndpointAuthMethod` `none` (the default is `client_secret_basic`) and with redirect and post-logout redirect URIs on a private-use scheme containing a period (`com.example.app:/cb`), on `https`, or on `http` to a loopback host. Credentials of each installation reach the server through dynamic registration or an `ITenantClientRegistrationStore`. Dynamic registration of a native client refuses a private-use scheme without a period, and a claimed `https` redirect registers as a web client with `token_endpoint_auth_method` `none`.
- A client declared in the tenant settings whose `RedirectUris` or `PostLogoutRedirectUris` hold a relative URI, a URI with a fragment, or a `javascript`, `data` or `vbscript` URI stops the host at startup, naming the client. A tenant read from a store with such a client is left out, with an error in the log. A client listing a working absolute URI beside such an entry is corrected before the upgrade.
- Outbound requests to addresses a client supplies (key sets, request objects, sector identifiers, back-channel logout and CIBA notifications, Shared Signals push delivery, client metadata documents) use no proxy unless one is named: neither the system proxy nor `HTTP_PROXY` and `HTTPS_PROXY`. A deployment that leaves its network through a forward proxy sets `SecureHttpFetchOptions.OutboundProxy`, and `SharedSignalsTransmitterOptions.OutboundProxy` for push delivery. A value that is not an absolute `http`, `https`, `socks4`, `socks4a`, `socks5` or `socks5h` address without a path, query or fragment, with a port where the scheme has no default one, stops the host at startup, and so does an invalid `SecureHttpFetchOptions.AllowedDestinations` entry. With a proxy, the server still refuses an address its own lookup returns, but the proxy resolves the name again.
- These requests refuse HTTP/3: a request with `Version` 3.0 or higher, or with `VersionPolicy` `RequestVersionOrHigher`. With `BlockPrivateNetworks` on, they refuse every block of the IANA special-purpose address registries, the documentation, benchmarking, AS112 and AMT blocks among them.
- A class derived from `AddressValidatingHttpMessageHandler` judges the request URI in `GuardAsync` and the resolved addresses by the rule `AddressRuleFor` returns; one that overrides only `GuardAsync` connects without judging the address, so it overrides `AddressRuleFor` too. The handler under the guard is not an `HttpClientHandler`, and the synchronous `Send` throws `NotSupportedException`. A refused address arrives as `OutboundAddressRefusedException`, an `HttpRequestException`.
- The receiver address of push delivery is judged by the primary handler of the client named `PushDeliveryTransport.HttpClientName`. `ConfigurePrimaryHttpMessageHandler` or `UseSocketsHttpHandler` on that client, or on a client of the server's secure fetch, replaces the guard; add handlers with `AddHttpMessageHandler`. `PushDeliverySender.SendPendingAsync` returns a failed pass for a refused receiver instead of throwing: nothing is sent, the events stay queued, and a warning names the stream.
- `RegistrationClientUriBuilder.Build` reads the tenant from `HttpContext.RequestServices`, so a host calling it over an `HttpContext` it built itself supplies request services.
- The compiler-generated equality of `ClientRegistrationRequest` compares whether `offline_access` was stated, so a request without the member is not equal to one stating `consent_required`, although both read `OfflineAccess` as `ConsentRequired`.
- These outbound requests take their TLS options from `AddressValidatingHttpMessageHandler.SslOptions`, where a host sets a private certificate authority or a client certificate. By default they download no certificate the endpoint's chain names and check no revocation online, so an endpoint that serves its certificate without its intermediate certificates is refused, and on Windows so is one whose public root is not yet in the local store. A host that needs downloads sets its own `CertificateChainPolicy` there.
- An ID token carries `sid` only for a client with `BackChannelLogout` set, or with `FrontChannelLogout` whose `RequiresSessionId` is true. A logout request whose `id_token_hint` carries no `sid` always shows the confirmation page, so the end users of a client without session logout confirm every logout. Such an ID token is refused as the `subject_token` or `actor_token` of a token exchange.
- A client gets a refresh token only when it may redeem one: its `AllowedGrantTypes` include `refresh_token`, or token exchange with `TokenExchangeAllowedSubjectTokenTypes` admitting the refresh token type. For any other client `offline_access` is dropped at the authorization, device authorization and backchannel authentication requests and at the token endpoint, so the end user is not asked to consent to it and no access token carries it. A client with no `AllowedGrantTypes` takes `authorization_code` only, and so gets no refresh token until `refresh_token` is added. A host's `IUserDeviceAuthenticationHandler` shows the end user `ValidBackChannelAuthenticationRequest.Scope`, which leaves a dropped `offline_access` out, rather than `Model.Scope`.
- A token issued by token exchange belongs to the session of its subject token, carries that sign-in's `auth_time`, `acr` and `amr`, and expires no later than the subject token, so revoking the session revokes the exchanged token too. A JWT subject or actor token without `sid` or `auth_time` is refused. A token exchanged again without an `actor_token` keeps the subject token's `act`.
- `SubjectTokenContext` gains the required `SessionId` and `AuthenticationTime` and the optional `IdentityProvider`, `AuthContextClassRef` and `AuthenticationMethodReferences`: a host's `ISubjectTokenResolver` sets the two required members or does not compile (CS9035), and returns `Subject` and every `sub` of `Act` as real identifiers, never a pairwise pseudonym. `TokenExchangeGrantHandler` takes only an `IServiceProvider`, and `RefreshTokenSubjectTokenResolver` takes an `IRevocationCutoffChecker` as its fourth parameter, so a host constructing either itself changes the call.
- A failure a subject token resolver returns reaches the client as `invalid_request`, its description prefixed with `subject_token:` or `actor_token:`; only `server_error` and `temporarily_unavailable` pass as the resolver wrote them. A subject token too close to its expiry to give the new token any lifetime is refused with `invalid_request` too.
- Only `AuthorizationCodeGrantHandler` compares the token request's `redirect_uri` with the grant's `AuthorizationContext.RedirectUri`; a host's own `IAuthorizationGrantHandler` that sets `RedirectUri` and needs the comparison makes it itself.
- A token issued to a pairwise client carries every `sub` of its `act` as that client's pseudonym, as it carries `sub`, so a delegated access token issued to such a client by 3.0 is refused until it expires. Introspection by a caller other than the token's client returns `act`: with the caller's own pseudonyms for a pairwise caller, and without any `sub` for another caller.
- The aliases `Sha256HashBase64`, `Sha512HashBase64`, `Sha256HashHex` and `Sha512HashHex` of `ClientSecret` are read from configuration only and are `[JsonIgnore]`, so JSON carries each hash once, as `Sha256Hash` or `Sha512Hash`. JSON written by 3.0 reads to the same hashes; a stored client written by hand with only an alias holds no hash after the upgrade.
- A tenant holding a null where its types declare a value (a member or a collection element whose nullable annotation rules null out) is refused alone, with `Tenant '<id>': <path> is null, where a value is required.` From the settings it stops the host at startup; from a store it is left out and the other tenants are served. Members 3.0 accepted as null count, such as a client's `TokenEndpointAuthMethod` or `UserInfoSignedResponseAlgorithm` written as null in a stored definition.

A host that registers no `IMemoryCache` or `IDistributedCache` starts on in-process caches of the library's own, and a cache the host registers is used whatever order it is registered in; `Abblix.JWT` references `Microsoft.Extensions.Caching.Memory` for them. Client ID Metadata Documents (`AddClientIdMetadataDocuments()`) are experimental and reported as `ABX9001`, see the [Abblix.OIDC.Server README](src/Abblix.Oidc.Server/README.md#client-id-metadata-documents). The [3.1 release notes](https://github.com/Abblix/Oidc.Server/releases/tag/v3.1) list every change.

## ⚠️ Upgrading to 3.0

Version 3.0 changes how a host registers and configures the server. The changes most hosts meet:

- The library targets .NET 11 only.
- Every server serves tenants. A deployment with one issuer declares one `TenantDefinition` in `OidcOptions.Tenants`, and the settings of an issuer (its clients, scopes, resources, keys, pages and security profile) move from `OidcOptions` into that definition.
- The host's own services are told the tenant of each call: `IUserInfoProvider.GetUserInfoAsync`, `IClientInfoProvider` and the other registries take a `TenantDefinition` as their first parameter.
- A host calls `app.UseMultiTenancy()` before its own routing when it serves several tenants, one tenant at an issuer with a path, or tenants from a store or catalog of its own. A host with one tenant at an issuer without a path does not need the call.
- An MVC host maps the endpoints with `app.MapOidcControllers()`, a Minimal API host with `app.MapOidcEndpoints()`.
- A host chooses how end-user consent is obtained, or it does not start: it registers its own `IUserConsentsProvider`, or calls `AddConsentGrantedForEveryClient()`.
- Neither logout channel is served unless the host registers it, with `AddBackChannelLogout()` or `AddFrontChannelLogout()`.
- Refresh token reuse is set by `RefreshTokenOptions.ReusePolicy`, and a client gets refresh tokens only as its `ClientInfo.OfflineAccess` allows, which is disabled unless set.
- Code that validates a JWT through the library states the token types it accepts in `ValidationParameters.TokenTypes`.
- A client signing its own authentication JWT names the issuer as its only audience, as RFC 10070 requires. While a client moves off the token endpoint address, the backchannel authentication endpoint address, the pushed authorization request endpoint address or an audience array, the host can let that one client keep its form with `ClientInfo.ClientAssertionAudiences`, and dynamically registered clients with `NewClientOptions.ClientAssertionAudiences`, except under FAPI 2.0.
- What 2.x stored is not read by 3.0, so end users sign in again, and grants, dynamic client registrations and minted keys of 2.x end once.

The complete list, with what each change asks of a host, is in the [3.0 release notes](https://github.com/Abblix/Oidc.Server/releases/tag/v3.0). The [Upgrading to 3.0](https://www.abblix.com/en/docs/upgrading-to-3.0) guide walks a 2.x deployment through the move, including how to keep the signing keys it minted.

## 📚 Documentation

### Getting Started
Explore the [Getting Started Guide](https://www.abblix.com/en/docs/getting-started-guide).
In this guide, you will create a working solution step by step, building an OpenID Connect Provider using ASP.NET MVC and the Abblix OIDC Server solution.

### Migrating from IdentityServer
[Migrating from IdentityServer4 or Duende](https://www.abblix.com/en/docs/migrate-from-identityserver) walks through a real migration end to end: dotnet/eShop's Identity.API moved from Duende IdentityServer onto Abblix OIDC Server, every decision named along the way.

### Shared Signals
[A working Shared Signals transmitter and receiver for ASP.NET Core](https://www.abblix.com/en/docs/shared-signals-guide) shows two hosts exchanging a signed Security Event Token over HTTPS, each verifying the other.

The [Documentation](https://www.abblix.com/en/docs/introduction-to-abblix-oidc-server) site covers configuration, deployment, the API reference and the OpenID Connect standard itself.

## 💎 Abblix Account

Prefer not to run the provider yourself? [Abblix Account](https://account.abblix.com) is a ready-to-use service hosted in the cloud, built on this library. You get passkeys, MFA, social login, and security event notifications: everything your users need, integrated into your website in minutes.

👉 See it live: [Quorvel Coffee](https://quorvel.abblix.com) is a demo application using Abblix Account for user authentication. It shows how sign-in flows, session management, and user self-service, all delivered by Abblix Account, fit into a client website.

## 🤝 Feedback and Contributions

The protocol surface is complete and passes the OpenID Foundation conformance plans it is tested against, but the library is not finished. What you run into in your own application is what we cannot see from here.

> [!IMPORTANT]
> Whether you have feedback on features, have encountered any bugs, or have suggestions for enhancements, we're eager to hear from you. A report that names the flow and the client you were using is what turns a guess into a fix.

Please feel free to contribute by [submitting an issue](https://github.com/Abblix/Oidc.Server/issues) or [joining the discussions](https://github.com/Abblix/Oidc.Server/discussions).

For how we handle contributions, and why the library is developed in-house, see our [Contributing Guidelines](CONTRIBUTING.md).

## 📃 License

This product is distributed under a source-available proprietary license. See 📋[License Agreement](LICENSE.md) for details.

It is free of charge for companies under $1M in annual revenue and under $1M raised in outside funding, for
non-profits, educational institutions, personal projects and non-commercial open source, and for development,
test and staging environments at any size. Every protocol is included at every tier, with no limit on client
applications or users, and one production issuer per free deployment. See the
[pricing page](https://www.abblix.com/en/oidc-server/pricing).

## 🗨️ Contacts

For more details about our products, services, or any general information regarding the Abblix OIDC Server, feel free to reach out to us. Below are the best ways to contact our team:

- General inquiries: [info@abblix.com](mailto:info@abblix.com)
- Support and security reports: [support@abblix.com](mailto:support@abblix.com), see the [Security Policy](SECURITY.md)
- Website: Visit the official Abblix OIDC Server page for more information: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server).

Subscribe to our LinkedIn and Twitter:

[![LinkedIn](https://img.shields.io/badge/subscribe-white.svg?logo=data:image/svg%2bxml;base64,PHN2ZyB2aWV3Qm94PSIwIDAgMjQgMjQiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHBhdGggZD0iTTIwLjQ0NyAyMC40NTJoLTMuNTU0di01LjU2OWMwLTEuMzI4LS4wMjctMy4wMzctMS44NTItMy4wMzctMS44NTMgMC0yLjEzNiAxLjQ0NS0yLjEzNiAyLjkzOXY1LjY2N0g5LjM1MVY5aDMuNDE0djEuNTYxaC4wNDZjLjQ3Ny0uOSAxLjYzNy0xLjg1IDMuMzctMS44NSAzLjYwMSAwIDQuMjY3IDIuMzcgNC4yNjcgNS40NTV2Ni4yODZ6TTUuMzM3IDcuNDMzYTIuMDYyIDIuMDYyIDAgMCAxLTIuMDYzLTIuMDY1IDIuMDY0IDIuMDY0IDAgMSAxIDIuMDYzIDIuMDY1em0xLjc4MiAxMy4wMTlIMy41NTVWOWgzLjU2NHYxMS40NTJ6TTIyLjIyNSAwSDEuNzcxQy43OTIgMCAwIC43NzQgMCAxLjcyOXYyMC41NDJDMCAyMy4yMjcuNzkyIDI0IDEuNzcxIDI0aDIwLjQ1MUMyMy4yIDI0IDI0IDIzLjIyNyAyNCAyMi4yNzFWMS43MjlDMjQgLjc3NCAyMy4yIDAgMjIuMjIyIDBoLjAwM3oiIGZpbGw9IiMwQTY2QzIiLz48cGF0aCBzdHlsZT0iZmlsbDojZmZmO3N0cm9rZS13aWR0aDouMDIwOTI0MSIgZD0iTTQuOTE3IDcuMzc3YTIuMDUyIDIuMDUyIDAgMCAxLS4yNC0zLjk0OWMxLjEyNS0uMzg0IDIuMzM5LjI3NCAyLjY1IDEuNDM3LjA2OC4yNS4wNjguNzY3LjAwMSAxLjAxYTIuMDg5IDIuMDg5IDAgMCAxLTEuNjIgMS41MSAyLjMzNCAyLjMzNCAwIDAgMS0uNzktLjAwOHoiLz48cGF0aCBzdHlsZT0iZmlsbDojZmZmO3N0cm9rZS13aWR0aDouMDIwOTI0MSIgZD0iTTQuOTE3IDcuMzc3YTIuMDU2IDIuMDU2IDAgMCAxLTEuNTItMi42NyAyLjA0NyAyLjA0NyAwIDAgMSAzLjQxOS0uNzU2Yy4yNC4yNTQuNDIuNTczLjUxMi45MDguMDY1LjI0LjA2NS43OCAwIDEuMDItLjA1MS4xODYtLjE5Ny41MDQtLjMuNjUyLS4wOS4xMzItLjMxLjM2Mi0uNDQzLjQ2NC0uNDYzLjM1Ny0xLjEuNTAzLTEuNjY4LjM4MlpNMy41NTcgMTQuNzJWOS4wMDhoMy41NTd2MTEuNDI0SDMuNTU3Wk05LjM1MyAxNC43MlY5LjAwOGgzLjQxMXYuNzg1YzAgLjYxNC4wMDUuNzg0LjAyNi43ODMuMDE0IDAgLjA3LS4wNzMuMTI0LS4xNjIuNTI0LS44NjUgMS41MDgtMS40NzggMi42NS0xLjY1LjI3NS0uMDQyIDEtLjA0NyAxLjMzMi0uMDA5Ljc5LjA5IDEuNDUxLjMxNiAxLjk0LjY2NC4yMi4xNTcuNTU3LjQ5My43MTQuNzEzLjQyLjU5Mi42OSAxLjQxMi44MDggMi40NjQuMDc0LjY2My4wODQgMS4yMTUuMDg1IDQuNTc4djMuMjU4aC0zLjUzNnYtMi45ODZjMC0yLjk3LS4wMS0zLjQ3NC0uMDc0LTMuOTA4LS4wOS0uNjA2LS4zMTQtMS4wODItLjYzNC0xLjM0Mi0uMzk1LS4zMjItMS4wMjktLjQzNy0xLjcwMy0uMzA5LS44NTguMTYzLTEuMzU1Ljc1LTEuNTIzIDEuNzk3LS4wNzYuNDcxLS4wODQuODQ1LS4wODQgMy44MzR2Mi45MTRIOS4zNTN6Ii8+PC9zdmc+)](https://www.linkedin.com/company/103540510/)
[![X](https://img.shields.io/badge/subscribe-white.svg?logo=data:image/svg%2bxml;base64,PHN2ZyB2aWV3Qm94PSIwIDAgMjQgMjQiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHBhdGggZD0iTTE4LjkwMSAxLjE1M2gzLjY4bC04LjA0IDkuMTlMMjQgMjIuODQ2aC03LjQwNmwtNS44LTcuNTg0LTYuNjM4IDcuNTg0SC40NzRsOC42LTkuODNMMCAxLjE1NGg3LjU5NGw1LjI0MyA2LjkzMlpNMTcuNjEgMjAuNjQ0aDIuMDM5TDYuNDg2IDMuMjRINC4yOThaIi8+PHBhdGggc3R5bGU9ImZpbGw6I2ZmZjtzdHJva2Utd2lkdGg6LjAyMDkyNDEiIGQ9Ik0xMS4wMzYgMTIuMDI4IDQuMzg3IDMuMzM0bC0uMDYtLjA4SDYuNDhsNi41MTYgOC42MTQgNi41NzUgOC42OTQuMDYuMDhoLTIuMDA2eiIvPjwvc3ZnPg==)](https://twitter.com/OIDCServer)

[Back to top](#top)
