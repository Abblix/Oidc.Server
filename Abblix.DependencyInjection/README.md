# Abblix DependencyInjection

**Abblix.DependencyInjection** extends Microsoft's default dependency injection framework with advanced patterns essential for building modular, extensible .NET applications. It enables service aliasing, composite services, decorators, and flexible registration overrides — all integrating seamlessly with `Microsoft.Extensions.DependencyInjection`.

## Key Features

- **Service Aliasing**: Register a service under multiple interfaces without duplicating instances, enabling flexible resolution patterns
- **Composite Services**: Combine multiple implementations of the same interface into a single composite, ideal for chain-of-responsibility and pipeline patterns
- **Decorator Pattern**: Wrap existing service registrations with cross-cutting concerns (logging, caching, validation) without modifying original implementations
- **Registration Overrides**: Override dependencies directly via type, instance, or factory — simplifying testing and environment-specific configurations
- **Lifetime Management**: Full support for Scoped, Singleton, and Transient lifetimes with advanced composition scenarios

## Installation

```bash
dotnet add package Abblix.DependencyInjection
```

## Usage Example

```csharp
services.AddSingleton<ITokenValidator, JwtTokenValidator>();

// Decorate with logging
services.Decorate<ITokenValidator, LoggingTokenValidator>();

// Add alias for alternate resolution
services.AddAlias<ISecurityTokenValidator, ITokenValidator>();
```

## Part of the Abblix OIDC Server Ecosystem

Abblix.DependencyInjection provides the modular architecture backbone for all Abblix packages:

| Package | Description |
|---------|-------------|
| **[Abblix.Utils](https://www.nuget.org/packages/Abblix.Utils)** | Utility library with crypto, URI, and JSON helpers |
| **Abblix.DependencyInjection** | Advanced .NET DI extensions *(this package)* |
| **[Abblix.JWT](https://www.nuget.org/packages/Abblix.JWT)** | JWT signing, encryption, and validation using .NET crypto primitives |
| **[Abblix.OIDC.Server](https://www.nuget.org/packages/Abblix.OIDC.Server)** | Core OpenID Connect server implementation |
| **[Abblix.OIDC.Server.MVC](https://www.nuget.org/packages/Abblix.OIDC.Server.MVC)** | ASP.NET MVC integration for OIDC server |

## Getting Started

To learn more about the Abblix OIDC Server product, visit our [Documentation](https://docs.abblix.com/docs) site and explore the [Getting Started Guide](https://docs.abblix.com/docs/getting-started-guide).

## Contacts

- **Email**: [support@abblix.com](mailto:support@abblix.com)
- **Website**: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server)
