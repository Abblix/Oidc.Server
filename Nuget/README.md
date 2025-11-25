# Abblix OIDC Server

**Abblix OIDC Server** is a robust .NET library that implements the OpenID Connect protocol on the server side. It is designed to meet high standards of flexibility, reusability, and reliability, using well-known software design patterns such as modular and hexagonal architectures. These patterns ensure that different parts of the library can work independently, improving the library's modularity, testability, and maintainability. The library also supports Dependency Injection using the standard .NET DI container, which aids in better organization and management of code. Specifically tailored for seamless integration with ASP.NET WebApi, Abblix OIDC Server employs standard controller classes, binding, and routing mechanisms to simplify the integration of OpenID Connect into your services.

## What's New in Version 2.0.0

🚨 **BREAKING CHANGES**
- **Result Pattern Migration**: Migrated to `Result<TSuccess, TFailure>` pattern for compiler-enforced explicit error handling and functional programming style
- **Framework Updates**: Dropped .NET 6 & 7 (EOL) - now targets .NET 8 (LTS), .NET 9 (STS), and .NET 10 (LTS - released Nov 2025, supported until Nov 2028)

🆕 **New Features**
- **client_secret_jwt**: Standards-compliant JWT-based client authentication method
- **Endpoint Configuration**: Attribute-based system for enabling/disabling endpoints
- **Grant Type Discovery**: Complete dynamic grant type reporting infrastructure
- **Device Authorization Grant**: RFC 8628 support for devices with limited input capabilities

🔒 **Security Enhancements**
- **SSRF Protection**: Configurable multi-layered protection with DNS rebinding prevention, IP blocking, scheme restrictions, and comprehensive logging
- **Enhanced Validation**: Type-safe JSON Web Key hierarchy with compile-time safety

⚠️ **Migration Required**: This is a major version update with breaking changes. Review your code for Result pattern usage and update error handling accordingly.

## NuGet Packages Description

- **Abblix.OIDC.Server**
  This core package implements the OpenID Connect (OIDC) server functionality, providing a robust, compliant, and extensible framework for adding OIDC-based authentication and authorization to .NET applications. It supports various OIDC flows and configurations, tailored for modern application security needs.

- **Abblix.OIDC.Server.MVC**
  Tailored for ASP.NET MVC applications, this package extends the Abblix.OIDC.Server to integrate smoothly with the MVC framework. It simplifies the process of securing MVC applications with OIDC, handling the intricacies of user authentication, session management, and secure redirections.

- **Abblix.JWT**
  The Abblix.JWT package facilitates handling of JSON Web Tokens (JWTs) within the .NET ecosystem. It builds on top of `System.IdentityModel.Tokens.Jwt` to provide utilities for token validation, generation, and management, making it essential for securing web applications and services that rely on stateless authentication mechanisms.

- **Abblix.DependencyInjection**
  This package extends Microsoft's default dependency injection (DI) framework. It allows for more advanced scenarios such as overriding dependencies directly via type, instance, or factory, aliasing services, and more complex service compositions and decorations. It integrates seamlessly, enhancing flexibility and maintainability of DI configurations in .NET applications.

- **Abblix.Utils**
  A utility package that provides common functionalities needed across various parts of the Abblix OIDC server implementation. These include helpers for logging, data manipulation, and other cross-cutting concerns that are essential for the operation and maintenance of security-focused services.

## Implemented technologies and standards

Abblix OIDC Server fully implements a comprehensive suite of advanced standards for authorization and security, providing a robust and secure environment for authorization data handling. Here are the key standards implemented in our product.

- **The OAuth 2.0 Authorization Framework**: [RFC 6749](https://tools.ietf.org/html/rfc6749): Defines procedures for secure authorization of applications.
- **The OAuth 2.0 Authorization Framework: Bearer Token Usage**: [RFC 6750](https://tools.ietf.org/html/rfc6750): Explains how to securely use bearer tokens to access resources.
- **OAuth 2.0 Token Revocation**: [RFC 7009](https://tools.ietf.org/html/rfc7009): Describes methods to securely cancel access and refresh tokens.
- **JSON Web Token (JWT)**: [RFC 7519](https://tools.ietf.org/html/rfc7519): Defines structure and use of JWTs for representing claims securely.
- **JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants**: [RFC 7523](https://tools.ietf.org/html/rfc7523): Uses JWTs for secure client authentication and as authorization grants.
- **Proof Key for Code Exchange by OAuth Public Clients**: [RFC 7636](https://tools.ietf.org/html/rfc7636): Improves security for public clients during authorization code exchange.
- **OAuth 2.0 Token Introspection**: [RFC 7662](https://tools.ietf.org/html/rfc7662): Allows resource servers to verify the active state and metadata of tokens.
- **OAuth 2.0 Dynamic Client Registration Protocol**: [RFC 7591](https://tools.ietf.org/html/rfc7591): Provides mechanisms for clients to register dynamically with authorization servers.
- **OAuth 2.0 Token Exchange**: [RFC 8693](https://tools.ietf.org/html/rfc8693): Details the method for a secure exchange of one token type for another.
- **JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens**: [RFC 9068](https://tools.ietf.org/html/rfc9068): Specifies the use of JWTs as OAuth 2.0 access tokens.
- **The OAuth 2.0 Authorization Framework: JWT-Secured Authorization Request (JAR)**: [RFC 9101](https://tools.ietf.org/html/rfc9101): Secures authorization requests using JWTs.
- **OAuth 2.0 Pushed Authorization Requests**: [RFC 9126](https://tools.ietf.org/html/rfc9126): Enhances security by allowing clients to push authorization requests directly to the server.
- **OAuth 2.0 Authorization Server Issuer Identification**: [RFC 9207](https://tools.ietf.org/html/rfc9207): Ensures the authenticity of authorization servers to clients.
- **OpenID Connect Core**: [Core Specification](https://openid.net/specs/openid-connect-core-1_0.html): Core functionality for OpenID Connect identity layer over OAuth 2.0.
- **OpenID Connect Discovery**: [Detailed Specification](https://openid.net/specs/openid-connect-discovery-1_0.html): Enables clients to discover provider configurations dynamically.
- **OpenID Connect RP-Initiated Logout**: [Detailed Specification](https://openid.net/specs/openid-connect-rpinitiated-1_0.html): Details logout initiated by relying parties.
- **OpenID Connect Session Management**: [Detailed Specification](https://openid.net/specs/openid-connect-session-1_0.html): Manages user session states in identity providers.
- **OpenID Connect Front-Channel Logout**: [Detailed Specification](https://openid.net/specs/openid-connect-frontchannel-1_0.html): Handles logout requests through front-channel communication.
- **OpenID Connect Back-Channel Logout**: [Detailed Specification](https://openid.net/specs/openid-connect-backchannel-1_0.html): Manages logout processes using back-channel communication.
- **OAuth 2.0 Multiple Response Type Encoding Practices**: [Core Specification](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html): Encodes different response types in OAuth 2.0 requests.
- **OAuth 2.0 Form Post Response Mode**: [Core Specification](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html): Transmits OAuth 2.0 responses via HTTP form posts.
- **OpenID Connect Dynamic Client Registration**: [Detailed Specification](https://openid.net/specs/openid-connect-registration-1_0.html): Enables OpenID Connect clients to register dynamically with providers.
- **OpenID Connect Core: Pairwise Pseudonymous Identifiers (PPID)**: [Core Specification](https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg): Implements a privacy mechanism by generating unique identifiers for clients.
- **OAuth 2.0 Resource Indicators**: [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707): Enables users to specify the resources they want access to, enhancing security and access control.
- **OpenID Connect Client-Initiated Backchannel Authentication (CIBA)**: [Core Specification](https://openid.net/specs/openid-connect-backchannel-1_0.html): Enables secure user authentication via backchannel communication on devices without direct web access, ideal for IoT and financial services scenarios.

## Getting Started

To better understand the Abblix OIDC Server product, we strongly recommend visiting our comprehensive [Documentation](https://docs.abblix.com/docs) site. Please explore the [Getting Started Guide](https://docs.abblix.com/docs/getting-started-guide), designed to provide you with all the necessary instructions and tips for a thorough understanding of our solution.

## Use our custom ChatGPT "Abblix OIDC Server Helper"

The **Abblix OIDC Server Helper** is a specialized ChatGPT designed to assist users and developers working with the Abblix OIDC Server. This AI-powered tool provides guidance, answers questions, and offers troubleshooting help regarding the OIDC Server implementation.

Explore the capabilities of this assistant by visiting the [Abblix OIDC Server Helper](https://chat.openai.com/g/g-1icXaNyOR-abblix-oidc-server-helper). Whether you're a new user trying to understand the basics or an experienced developer looking for specific technical details, this tool is here to help enhance your workflow and knowledge.

For more detailed interactions and to explore its full potential, access the assistant directly through the provided link.

## Contacts

For more details about our products, services, or any general information regarding the Abblix OIDC Server, feel free to reach out to us. We are here to provide support and answer any questions you may have. Below are the best ways to contact our team:

- **Email**: Send us your inquiries or support requests at [support@abblix.com](mailto:support@abblix.com).
- **Website**: Visit the official Abblix OIDC Server page for more information: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server).

We look forward to assisting you and ensuring your experience with our products is successful and enjoyable!
