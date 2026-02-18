# Abblix OIDC Server

**Abblix OIDC Server** is a robust .NET library that implements the OpenID Connect protocol on the server side. It is designed to meet high standards of flexibility, reusability, and reliability, using well-known software design patterns such as modular and hexagonal architectures. These patterns ensure that different parts of the library can work independently, improving the library's modularity, testability, and maintainability. The library also supports Dependency Injection using the standard .NET DI container, which aids in better organization and management of code. Specifically tailored for seamless integration with ASP.NET WebApi, Abblix OIDC Server employs standard controller classes, binding, and routing mechanisms to simplify the integration of OpenID Connect into your services.

## What's New in Version 2.0

⚡ **Breaking Changes**
- **Result Pattern Migration**: Migrated to `Result<TSuccess, TFailure>` pattern for compiler-enforced explicit error handling and functional programming style
- **Framework Updates**: Dropped .NET 6 & 7 (EOL) - now targets .NET 8 (LTS), .NET 9 (STS), and .NET 10 (LTS - released Nov 2025, supported until Nov 2028)

🚀 **Features**
- **mTLS Client Authentication (RFC 8705)**: Self-signed and PKI/CA validation with certificate-bound tokens
- **JWT Bearer Grant Type (RFC 7523)**: Service-to-service authentication using signed JWTs for secure API-to-API communication
- **Device Authorization Grant (RFC 8628)**: OAuth flow for input-constrained devices (smart TVs, IoT, CLI tools)
- **CIBA Ping/Push Modes & Long-Polling**: Complete delivery mode implementation with ping notifications, push token delivery, and long-polling support
- **client_secret_jwt Authentication**: JWT-based client authentication per OIDC Core spec
- **SSRF Protection**: Multi-layered defense with DNS validation and IP blocking
- **Protocol Buffer Serialization**: 40-60% smaller storage footprint with faster processing
- **ECDSA Certificate Support**: Enables compliance with modern security standards that mandate or prefer elliptic curve cryptography

> **Migration Required**: This is a major version update with breaking changes. Review your code for Result pattern usage and update error handling accordingly.

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
- **The OAuth 2.0 Authorization Framework**: [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749): Defines procedures for secure authorization of applications including authorization code, implicit, client credentials, and resource owner password credentials flows.
- **The OAuth 2.0 Authorization Framework: Bearer Token Usage**: [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750): Explains how to securely use bearer tokens to access resources.
- **OAuth 2.0 Token Revocation**: [RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009): Describes methods to securely cancel access and refresh tokens.
- **OAuth 2.0 Token Introspection**: [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662): Allows resource servers to verify the active state and metadata of tokens.
- **Proof Key for Code Exchange (PKCE)**: [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636): Improves security for public clients during authorization code exchange with S256 and plain methods.
- **OAuth 2.0 Device Authorization Grant**: [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628): Enables OAuth 2.0 authorization on devices with limited input capabilities (smart TVs, game consoles, IoT devices) by delegating user interaction to a secondary device. Includes brute force protection with exponential backoff and per-IP rate limiting (RFC 8628 Section 5.2), plus atomic device code redemption to prevent race conditions (RFC 8628 Section 3.5).
- **OAuth 2.0 Dynamic Client Registration Protocol**: [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591): Provides mechanisms for clients to register dynamically with authorization servers.
- **OAuth 2.0 Dynamic Client Registration Management Protocol**: [RFC 7592](https://datatracker.ietf.org/doc/html/rfc7592): Enables management operations (read, update, delete) for dynamically registered clients.
- **OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens**: [RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705): Provides mutual TLS authentication with PKI and self-signed certificate validation, plus certificate-bound tokens.
- **OAuth 2.0 Resource Indicators**: [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707): Enables clients to specify the resources they want access to, enhancing security and access control.
- **JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens**: [RFC 9068](https://datatracker.ietf.org/doc/html/rfc9068): Specifies the use of JWTs as OAuth 2.0 access tokens.
- **JWT-Secured Authorization Request (JAR)**: [RFC 9101](https://datatracker.ietf.org/doc/html/rfc9101): Secures authorization requests using JWTs.
- **OAuth 2.0 Pushed Authorization Requests (PAR)**: [RFC 9126](https://datatracker.ietf.org/doc/html/rfc9126): Enhances security by allowing clients to push authorization requests directly to the server.
- **OAuth 2.0 Authorization Server Issuer Identification**: [RFC 9207](https://datatracker.ietf.org/doc/html/rfc9207): Ensures the authenticity of authorization servers to clients.
- **OAuth 2.0 Multiple Response Type Encoding Practices**: [Specification](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html): Encodes different response types in OAuth 2.0 requests.
- **OAuth 2.0 Form Post Response Mode**: [Specification](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html): Transmits OAuth 2.0 responses via HTTP form posts.
- **JSON Web Signature (JWS)**: [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515): Defines digital signature and MAC methods for JSON data structures.
- **JSON Web Encryption (JWE)**: [RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516): Defines encryption methods for JSON data structures.
- **JSON Web Key (JWK)**: [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517): Defines a JSON representation of cryptographic keys.
- **JSON Web Algorithms (JWA)**: [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518): Defines cryptographic algorithms for use with JWS, JWE, and JWK.
- **JSON Web Token (JWT)**: [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519): Defines structure and use of JWTs for representing claims securely.
- **JWT Profile for OAuth 2.0 Client Authentication and Authorization Grants**: [RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523): Uses JWTs for secure client authentication (private_key_jwt, client_secret_jwt) and as authorization grants.
- **Authentication Method Reference Values**: [RFC 8176](https://datatracker.ietf.org/doc/html/rfc8176): Defines standardized values for the `amr` (Authentication Methods References) JWT claim, enabling interoperable communication of authentication methods (password, OTP, biometrics, MFA, smart card, etc.).
- **OpenID Connect Core 1.0**: [Specification](https://openid.net/specs/openid-connect-core-1_0.html): Core functionality for OpenID Connect identity layer over OAuth 2.0, including ID Token issuance, standard claims, and authentication flows.
- **OpenID Connect Discovery 1.0 / OAuth 2.0 Authorization Server Metadata**: [Specification](https://openid.net/specs/openid-connect-discovery-1_0.html), [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414): Enables clients to discover provider configurations dynamically via the well-known endpoint.
- **OpenID Connect Dynamic Client Registration 1.0**: [Specification](https://openid.net/specs/openid-connect-registration-1_0.html): Enables OpenID Connect clients to register dynamically with providers.
- **OpenID Connect Session Management 1.0**: [Specification](https://openid.net/specs/openid-connect-session-1_0.html): Manages user session states in identity providers with check_session_iframe support.
- **OpenID Connect RP-Initiated Logout 1.0**: [Specification](https://openid.net/specs/openid-connect-rpinitiated-1_0.html): Details logout initiated by relying parties via the end-session endpoint.
- **OpenID Connect Front-Channel Logout 1.0**: [Specification](https://openid.net/specs/openid-connect-frontchannel-1_0.html): Handles logout requests through front-channel communication.
- **OpenID Connect Back-Channel Logout 1.0**: [Specification](https://openid.net/specs/openid-connect-backchannel-1_0.html): Manages logout processes using back-channel communication with logout tokens.
- **OpenID Connect Client-Initiated Backchannel Authentication (CIBA)**: [Specification](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html): Enables secure user authentication via backchannel communication on devices without direct web access, ideal for IoT and financial services scenarios. Supports three delivery modes: poll (client polls token endpoint), ping (server notifies client at callback), push (server delivers tokens to notification endpoint)
- **Pairwise Pseudonymous Identifiers (PPID)**: [OpenID Connect Core Section 8](https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg): Implements a privacy mechanism by generating unique subject identifiers per client.

## Getting Started

To better understand the Abblix OIDC Server product, we strongly recommend visiting our comprehensive [Documentation](https://docs.abblix.com/docs) site. Please explore the [Getting Started Guide](https://docs.abblix.com/docs/getting-started-guide), designed to provide you with all the necessary instructions and tips for a thorough understanding of our solution.

## Contacts

For more details about our products, services, or any general information regarding the Abblix OIDC Server, feel free to reach out to us. We are here to provide support and answer any questions you may have. Below are the best ways to contact our team:

- **Email**: Send us your inquiries or support requests at [support@abblix.com](mailto:support@abblix.com).
- **Website**: Visit the official Abblix OIDC Server page for more information: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server).

We look forward to assisting you and ensuring your experience with our products is successful and enjoyable!
