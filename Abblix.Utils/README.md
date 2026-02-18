# Abblix Utils

**Abblix.Utils** is a comprehensive utility library for .NET that provides essential cross-cutting functionalities used throughout the Abblix OIDC Server ecosystem. It includes advanced URI and string manipulation tools, cryptographic helpers, custom JSON converters, and asynchronous utilities — all designed for security-focused applications.

## Key Features

- **URI Manipulation**: Advanced parsing and construction of complex URI components, including query strings and fragment handling
- **String Extensions**: Extended string operations for common patterns in authentication and authorization workflows
- **Cryptographic Utilities**: Secure random data generation, Base32/Base64URL encoding, and key material helpers using .NET crypto primitives
- **JSON Serialization**: Custom `System.Text.Json` converters for efficient processing of security tokens and protocol messages
- **Asynchronous Utilities**: Helpers for async enumeration and task coordination
- **Caching Abstractions**: Extensions for `IDistributedCache` with typed serialization support
- **HTTP Abstractions**: Lightweight HTTP request/response helpers built on `Microsoft.AspNetCore.Http.Abstractions`

## Installation

```bash
dotnet add package Abblix.Utils
```

## Part of the Abblix OIDC Server Ecosystem

Abblix.Utils is the foundational utility layer used by all other Abblix packages:

| Package | Description |
|---------|-------------|
| **Abblix.Utils** | Utility library *(this package)* |
| **[Abblix.DependencyInjection](https://www.nuget.org/packages/Abblix.DependencyInjection)** | Advanced .NET DI extensions with aliasing, composites, and decorators |
| **[Abblix.JWT](https://www.nuget.org/packages/Abblix.JWT)** | JWT signing, encryption, and validation using .NET crypto primitives |
| **[Abblix.OIDC.Server](https://www.nuget.org/packages/Abblix.OIDC.Server)** | Core OpenID Connect server implementation |
| **[Abblix.OIDC.Server.MVC](https://www.nuget.org/packages/Abblix.OIDC.Server.MVC)** | ASP.NET MVC integration for OIDC server |

## Getting Started

To learn more about the Abblix OIDC Server product, visit our [Documentation](https://docs.abblix.com/docs) site and explore the [Getting Started Guide](https://docs.abblix.com/docs/getting-started-guide).

## Contacts

- **Email**: [support@abblix.com](mailto:support@abblix.com)
- **Website**: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server)
