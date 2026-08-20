# Abblix.DependencyInjection

Extensions over `Microsoft.Extensions.DependencyInjection` for the patterns a modular library actually needs: aliasing one registration under several contracts, composing many implementations into one pipeline and editing that pipeline afterwards, decorating registered services, and constructing services with per-call overrides. This is the DI layer behind Abblix OIDC Server, usable on its own in any .NET application.

## Install

```bash
dotnet add package Abblix.DependencyInjection
```

## Aliasing

One implementation, several contracts, one instance:

```csharp
services.AddSingleton<TokenService>();
services.AddAlias<ITokenIssuer, TokenService>();
services.AddAlias<ITokenRevoker, TokenService>();
```

`TryAddAlias` and `TryAddEnumerableAlias` follow the framework's TryAdd semantics, so a host's own registration wins over a library default.

## Composition: many implementations behind one contract

`Compose` collapses a family of registrations into a single composite behind the singular contract - the shape of a validation pipeline, a chain of handlers, a set of strategies consulted in order:

```csharp
services.AddTransient<IValidator, SyntaxValidator>();
services.AddTransient<IValidator, BusinessRuleValidator>();
services.Compose<IValidator, CompositeValidator>();
```

What makes this composition editable is `Decompose`: a live cursor over the composed members that a host uses to adjust a pipeline a library assembled, without rebuilding it:

```csharp
services.Decompose<IValidator>()
    .AddBefore<BusinessRuleValidator>(ServiceDescriptor.Transient<IValidator, TenantPolicyValidator>())
    .Remove<SyntaxValidator>();
```

Members keep their own lifetimes, the composite adopts the shortest among them, and edits act on the registrations themselves - there is no hidden side registry to drift out of sync.

## Decoration

`Decorate` wraps whatever is currently registered, preserving its lifetime - the standard way to add a cross-cutting concern without touching the original registration:

```csharp
services.Decorate<ITokenValidator, LoggingTokenValidator>();
```

Both operations have keyed counterparts: `ComposeKeyed` and `DecorateKeyed`.

## Per-call overrides

`Dependency.Override` constructs a service from the container while substituting only the named dependencies - the clean alternative to hand-built factories that freeze a constructor's shape into calling code:

```csharp
services.AddSingleton<IReplayCache>(provider =>
    provider.CreateService<DistributedReplayCache>(
        Dependency.Override("Abblix.SecurityEvents:ReplayPrevention:")));
```

Overloads accept a type mapping, an instance, or a factory, and the same overrides ride the `AddSingleton` / `AddScoped` / `AddTransient` overloads this package adds. Every dependency not overridden resolves from the container as usual, so a new constructor parameter on the service does not break the factory.

## Registration inspection

`Find`, `FindRequired`, `FindAll`, `RemoveAll` and `ChangeLifetime` operate on the registration list itself - the tools for the rare but real cases where a host must inspect or reshape what a library registered.

## Part of the Abblix product family

The composition and decoration machinery here is what lets [Abblix.OIDC.Server](https://www.nuget.org/packages/Abblix.OIDC.Server) ship assembled pipelines a host can still edit; the full family lives in the [repository](https://github.com/Abblix/Oidc.Server).

## License

Abblix.DependencyInjection is licensed under the [Apache License 2.0](https://github.com/Abblix/Oidc.Server/blob/master/LICENSES/Apache-2.0.txt).

## Contacts

- General inquiries: [info@abblix.com](mailto:info@abblix.com)
- Support and security reports: [support@abblix.com](mailto:support@abblix.com)
- Website: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server)
