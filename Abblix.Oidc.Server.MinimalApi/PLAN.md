# Abblix.Oidc.Server.MinimalApi — design and roadmap

Work-in-progress plan for a Minimal API transport adapter that mirrors the existing MVC integration over the same framework-neutral core (`Abblix.Oidc.Server`). This document is the roadmap for the `feature/minimal-api-adapter` branch.

## Architecture

The core (handlers, models, `DeclarativeValidation` markers, implicit operators) is already framework-neutral. The MVC project is a thin transport skin; this project is a **second, parallel skin over the same core** — not a refactor of the MVC one.

Two facts force "parallel" over "share":

- Every MVC formatter returns `ActionResult` / `ActionResult<T>`. `ActionResult` does **not** implement `IResult` — disjoint hierarchies. A parallel `IResult`-returning formatter set is required.
- The MVC source generator emits MVC-only binding attributes (`[BindProperty]`, `[ModelBinder]`, `[FromHeader]`). Its input-analysis half is reusable; its emit half is MVC-specific and must be retargeted.

## Decisions taken

- **Host-facing API** mirrors MVC: `AddOidcMinimalApi(...)` (registration) and `app.MapOidcEndpoints()` (returns the `RouteGroupBuilder`, replaces `app.MapControllers()`).
- **Routes** are a plain `OidcRouteOptions` POCO with literal defaults (`/connect/*`, `/.well-known/*`), overridable via the options pattern — replaces the MVC `[route:token?fallback]` application-model convention.
- **Enable/disable** is conditional `MapXxx` under `OidcOptions.EnabledEndpoints.HasFlag(...)` — same 404 semantics as the MVC `EnabledByConvention`, evaluated at map time.
- **Discovery URLs** resolve from `OidcRouteOptions` plus the request base URL, not from a mapped-endpoint lookup, so they are correct regardless of how many endpoints are mapped yet — and faithful to how MVC builds them from route templates.
- **Binding** (future, form-bound endpoints): a generator-emitted `static ValueTask<T?> BindAsync(HttpContext)` per request DTO; the request DTO and `ClientRequest` are two separately custom-bound parameters (custom binding does not count against Minimal API's single-form-parameter rule).
- **Validation** (future): a group-scoped `IEndpointFilter` running `Validator.TryValidateObject`, short-circuiting to the OAuth `invalid_request` result — kept group-scoped, never a global option a host could clobber.
- **Shared neutral code**: for now the adapter carries its own small HttpContext helpers (`HttpRequestExtensions`, `HttpRequestInfoProvider`) rather than touching the shipping MVC package. The heavier neutral pieces (the ~280-line auth-session adapter, parameter providers, error policy) are candidates for a future shared `Abblix.Oidc.Server.Http` package; extraction is deferred until the interactive endpoints need them.

## Slice status

- **Done — JWKS** (`GET /.well-known/jwks`): no input, no formatter. Verified at runtime; output is byte-for-byte structurally identical to the MVC host.
- **Done — Discovery** (`GET /.well-known/openid-configuration`): first formatter port to `IResult`; endpoint-URL resolution; null-omission confirmed. Verified at runtime (48 fields, all endpoint URLs absolute and correct).
- **Done — Check session** (`GET /connect/checksession`): custom HTML `IResult` (per-request CSP nonce) plus the caching decorator. Verified at runtime — text/html, CSP header, fresh nonce per request while the template is cached.
- **Done — Token** (`POST /connect/token`): the hardest form-encoded case. Request and `ClientRequest` each bound from the one posted form via their own `BindAsync`; client authentication, the `OidcError` to `IResult` error policy, and the no-cache headers all ported. Verified at runtime end-to-end — `client_credentials` issues a token (200, no-store headers), a wrong secret returns 401 with a Basic challenge (RFC 6749 §5.2), an unknown scope returns 400 `invalid_scope`. Binding is hand-written for now; the generator retarget is a separate follow-up.
- **Done — Revoke + Introspect** (`POST /connect/revoke`, `/connect/introspect`): same two-custom-bound-params pattern as token. Verified at runtime via a full lifecycle — issue → introspect(active=true) → revoke(200) → introspect(active=false) → bad-cred(401 invalid_client). Introspection ports both the RFC 7662 JSON and the RFC 9701 signed-JWT branch.
- **Done — PAR** (`POST /connect/par`): the richest form-encoded request. The full `AuthorizationRequest` binding is hand-written and exercises every special form-field shape — space-separated (`scope`, `response_type`, `acr_values`), JSON-in-a-field (`claims`, `authorization_details`), integer seconds (`max_age`), culture lists (`ui_locales`, `claims_locales`), and URIs. `AuthorizationRequest.BindAsync` reads query-or-form, so it also unblocks the authorize endpoint. Verified at runtime end-to-end — a rich PAR request returns 201 with a `request_uri`.
- **Done — bc-authorize, device, userinfo**: ported by a parallel authoring workflow (new files only), wiring consolidated single-thread. bc-authorize (3-param formatter, error subtypes), device (RFC 8628 response DTO + options), userinfo (query-or-form, JSON-or-signed-JWT, dual DPoP+Bearer challenge on 401 — added the second `OidcResults.Format` overload). All verified at runtime.
- **Done — authorize** (`GET|POST /connect/authorize`): the heaviest formatter — query/fragment redirect, form_post via a custom `IResult` (ported `AutoPostFormatter`), JARM, the session_state cookie, and interaction-page redirects with `IUriResolver` replaced by request-base resolution. Verified at runtime — a no-session GET redirects (302) to the login page carrying `request_uri`.
- **Done — endsession** (`GET|POST /connect/endsession`): front-channel HTML / post-logout redirect / 204, plus the cookie-delete decorator (new shared `WithAppendCookie`/`WithDeleteCookie` decorators). Verified at runtime.
- **Done — client management** (`POST /connect/register`, `GET|PUT|DELETE /connect/register/{clientId}`): JSON body via native `[FromBody]`, `{clientId}` via `BindAsync` over route values, Authorization header parsed; `registration_client_uri` from request base + route options; core response types reused. Verified at runtime.

**All 16 endpoints are ported and build clean (net8/9/10, 0 warnings).**

- **Done — Source generator retarget**: `Abblix.Oidc.Server.MinimalApi.SourceGeneration` is a sibling generator of the MVC one. It triggers on `[GeneratedFrom(typeof(Core.X), SupportsGet=...)]` stubs and emits the bound properties, a `static ValueTask<X?> BindAsync(HttpContext)`, and the implicit projection onto the core model. All nine request models (Token, Revocation, Introspection, Client, Authorization, BackChannelAuthentication, Device, UserInfo, EndSession) are now generated; the generated output is byte-for-byte equivalent to the hand-written models it replaced. The two generators share only framework-neutral plumbing (7 source-linked value-type / polyfill files); the input analysis and the emit half each live in their own generator. The generator project is registered in `Abblix.Oidc.slnx` under `/src/` and referenced from the runtime project as a build-time-only analyzer.
- **Done — E2E test host + tests**: `Abblix.Oidc.Server.MinimalApi.E2E.TestHost` mirrors the MVC `E2E.TestHost` (same client config / license / stubs, source-linked) but wires `AddOidcMinimalApi` + `MapOidcEndpoints`. `Abblix.Oidc.Server.MinimalApi.E2E.Tests` drives it through `WebApplicationFactory<Program>` (18 tests across binding, formatter and routing dimensions). Both projects are in `Abblix.Oidc.slnx` under `/tests/`. The Minimal API host registers `AddMemoryCache` / `AddCors` / `AddAuthorization` / `options.DeviceAuthorization` explicitly — the MVC host received the first three transitively through `AddControllersWithViews`.
- **Done — model validation**: the generator now translates the core declarative markers (`AllowedValues`, `AbsoluteUri`, `ElementsRequired`, `[Required]`) into executable validation attributes in `Abblix.Oidc.Server.MinimalApi.Attributes` (own copies, one `ValidationAttribute` per rule, mirroring `Mvc/Attributes`) emitted onto the generated model, which now implements the `IValidatableModel` marker. A group-scoped `ValidationEndpointFilter` runs `Validator.TryValidateObject` over the bound request models and shapes a violation as the OAuth `invalid_request` response — the counterpart of MVC's `[ReturnsOidcInvalidRequest]`, confined to the OIDC route group so a host cannot clobber it. `GeneratedFromAttribute` moved to the `Attributes/` folder to match the MVC layout.

## Known issues found while building

- **Core bug — device endpoint handler never registered. FIXED on develop (commit 7b4a6e1).** `AddDeviceAuthorizationEndpoint()` (which registers `IDeviceAuthorizationHandler`) had no callers — `AddEndpoints()` wired every endpoint handler except the device one — so `/connect/deviceauthorization` was non-functional in **both** adapters. In MVC the symptom is a clear "unable to resolve `IDeviceAuthorizationHandler`"; in Minimal API the unregistered handler is mis-inferred as a `[FromBody]` parameter and the endpoint returns a confusing 415. Fix added `.AddDeviceAuthorizationEndpoint()` to `AddEndpoints()`. An audit of all 52 core registration methods confirmed device was the only accidental omission (Implicit Flow / Password Grant are deliberately `Enable*` opt-ins, off by default for security).
- **Robustness follow-up.** To turn that mis-inference into a clear error, annotate the injected handler/formatter delegate parameters with `[FromServices]` (matches the MVC controllers). Not required for correctness when features are registered.

## Host responsibilities (same as the MVC integration)

The host wires caching (`AddMemoryCache`, `AddDistributedMemoryCache`), authentication, and the application services the core needs (for example `IUserInfoProvider`). The adapter supplies only the transport: endpoints, formatters, and the HttpContext-backed `IRequestInfoProvider`.
