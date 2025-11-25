# Changelog

All notable changes to Abblix OIDC Server will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0] - 2025-11-XX

### 🚨 BREAKING CHANGES

- **Result Pattern Migration**: Completely migrated to `Result<TSuccess, TFailure>` pattern for more explicit error handling and better functional programming support (#34)
  - All handler methods now return `Result<TSuccess, TFailure>` instead of throwing exceptions or returning nullable types
  - Use `TryGetSuccess()` and `TryGetFailure()` methods to handle results
  - See [MIGRATION-2.0.md](MIGRATION-2.0.md) for detailed migration guide

- **Framework Support Changes**: Dropped .NET 6 and .NET 7 support
  - Now exclusively targets .NET 8 (LTS) and .NET 9
  - .NET 6 reached end of support in November 2024
  - .NET 7 reached end of support in May 2024

- **API Simplification**: All response types renamed to remove redundant 'Response' suffix
  - `SuccessfulAuthorizationResponse` → `SuccessfulAuthorization`
  - `AuthorizationErrorResponse` → `AuthorizationError`
  - Similar pattern applied across all endpoint response types

- **IRequestInfoProvider Interface Changes**: Added `RemoteIpAddress` property
  - `IRequestInfoProvider.RemoteIpAddress` returns `System.Net.IPAddress?` for client IP logging
  - Custom implementations must implement this new property

- **JsonWebTokenHeader Changes**: Added `KeyId` property
  - `JsonWebTokenHeader.KeyId` exposes the `kid` header claim for audit logging

- **CIBA Interface Renaming**: Renamed CIBA notification interfaces for improved clarity
  - `IBackChannelAuthenticationNotifier` → `IBackChannelDeliveryModeRouter` (routes to appropriate delivery mode handler)
  - `IBackChannelAuthenticationStatusNotifier` → `IBackChannelLongPollingNotifier` (long-polling signaling infrastructure)
  - `IBackChannelNotificationService` → `IBackChannelPingNotifier` (HTTP ping notifications)
  - Corresponding implementation classes renamed: `InMemoryBackChannelAuthenticationStatusNotifier` → `InMemoryBackChannelLongPollingNotifier`, `HttpBackChannelNotificationService` → `HttpBackChannelPingNotifier`

### 🔒 Security

- Enhanced Device Authorization Grant with brute force protection and race condition prevention (7eaa064)
  - **Rate Limiting**: Exponential backoff per user code (configurable, default: 3 failures); per-IP sliding window (default: 10/minute); Result<bool, TimeSpan> pattern for type-safe retry handling; configurable thresholds in DeviceAuthorizationOptions; protobuf-based distributed state storage; security event logging (RFC 8628 Section 5.2)
  - **Atomic Operations**: Lock-based get-and-remove protocol prevents concurrent token requests from claiming the same device code, ensuring exactly one token issuance per code (RFC 8628 Section 3.5)

- Enhanced SSRF (Server-Side Request Forgery) protection with multi-layered security approach (498253c)
  - Added DNS resolution validation before HTTP requests
  - Implemented IP-based blocking for private network ranges
  - Added comprehensive logging for security events
  - Note: TOCTOU vulnerability exists between DNS validation and HTTP request

- Applied SSRF protection to client JWKS fetching
  - Updated `ClientKeysProvider` to use `ISecureHttpFetcher` instead of direct HTTP calls
  - Consistent security approach across JWT Bearer and client authentication flows
  - Enhanced error handling and logging for JWKS fetch operations

- Hardened GitHub Actions workflow against supply chain attacks (f96372e)
  - Pinned all GitHub Actions to commit SHA instead of mutable version tags
  - Secured secret handling with environment variables instead of inline expansion

- Added explicit `AttributeUsage` to validation attributes (ac61f96)

### ✨ Features

- **JWT Bearer Grant Type (RFC 7523)**: Full implementation of JWT Bearer grant type for token exchange scenarios
  - **Configuration-Based Setup**: Added `JwtBearerOptions` to `OidcOptions` for declarative trusted issuer configuration
  - **Trusted Issuer Management**: Configure external identity providers via `OidcOptions.JwtBearer.TrustedIssuers` collection
  - **Automatic JWKS Fetching**: Default `JwtBearerIssuerProvider` automatically fetches signing keys from configured JWKS URIs
  - **RFC 7523 Compliance**: Proper validation of issuer (iss), subject (sub), audience (aud), and expiration (exp) claims
  - **Signature Verification**: Resolves signing keys from trusted issuers' JWKS endpoints for JWT signature validation
  - **Audience Validation**: Ensures JWT audience matches the token endpoint URI where assertion is presented
  - **Federation Support**: Enables service-to-service authentication, token exchange, and cross-domain SSO scenarios
  - **Extensibility**: `IJwtBearerIssuerProvider` interface allows custom issuer validation strategies
  - **Security Hardening**: Multiple attack prevention mechanisms
    - Algorithm substitution attack prevention with configurable allowed algorithms (defaults to RS/ES/PS only, no HMAC or 'none')
    - Token type (`typ` header) validation to prevent token confusion attacks
    - Maximum JWT age (`MaxJwtAge`) validation with required `iat` claim to prevent stale token reuse
    - Replay protection via `jti` claim tracking with configurable `RequireJti` option
    - Maximum JWT size limit (`MaxJwtSize`) to prevent denial-of-service attacks
    - Scope restriction per trusted issuer via `AllowedScopes` configuration
    - Strict vs permissive audience validation modes via `StrictAudienceValidation` option
  - **Enhanced Audit Logging**: Security-critical logging with client IP address and JWT key ID (`kid`)
  - **Comprehensive Test Coverage**: 42 unit tests covering all RFC 7523 validation requirements and security scenarios

- Implemented Device Authorization Grant (RFC 8628) for input-constrained devices (1e1ed21)
  - Complete OAuth 2.0 flow for smart TVs, streaming devices, game consoles, and IoT devices
  - Device authorization endpoint (`/device_authorization`) with device code and user code generation
  - Token endpoint support for `urn:ietf:params:oauth:grant-type:device_code` grant type
  - User code verification service with customizable authentication UI
  - Status tracking: pending, authorized, denied, expired
  - Configurable numeric and base-20 user code formats with adjustable length and expiration
  - Protocol Buffer serialization for device authorization state
  - Validation framework for client types, scopes, and resources per RFC 8628
  - Enhanced with rate limiting and atomic operations in commit 7eaa064 (see Security section)

- **CIBA Ping and Push Mode Implementation**: Complete status notification and token delivery infrastructure for Client-Initiated Backchannel Authentication
  - **Long-Polling Support**: Added configurable long-polling timeout for token endpoint
    - Holds polling requests until authentication completes or timeout expires
    - Reduces server load and latency compared to repeated short polls
    - Configurable via `BackChannelAuthenticationOptions.LongPollingTimeout` (default: 30 seconds)
  - **Ping Mode**: Added `IBackChannelLongPollingNotifier` interface for real-time status change notifications
    - Implemented `InMemoryBackChannelLongPollingNotifier` with async notification support via TaskCompletionSource
    - Enables efficient long-polling without repeatedly querying storage
    - Server notifies client at callback endpoint when authentication completes via `IBackChannelPingNotifier`
  - **Push Mode**: Added `IBackChannelTokenDeliveryService` interface for token delivery abstraction
    - Implemented `HttpBackChannelTokenDeliveryService` for direct token delivery to clients
    - Server delivers tokens directly to client notification endpoint upon completion
  - Extended `IBackChannelAuthenticationStorage` with `UpdateAsync` and `TryRemoveAsync` methods for atomic operations
  - Strategy pattern implementation for delivery modes (poll/ping/push) via keyed DI with `IBackChannelDeliveryModeRouter`

- **Distributed Cache Utilities**: Added atomic get-and-remove operation for race condition prevention
  - `DistributedCacheExtensions.TryGetAndRemoveAsync()` implements 4-step last-write-wins protocol
  - Comprehensive test coverage including 100-thread concurrency scenarios
  - Works with Redis, SQL Server, and in-memory distributed cache implementations

- Implemented `client_secret_jwt` authentication method (#35, 6f4d240)
  - Full support for JWT-based client authentication per RFC 7523

- Added cache control headers to token responses per OIDC specification (a2d51f1)
  - Prevents caching of sensitive token data

- Enhanced dependency injection with keyed service decoration (#30, 63c40aa)
  - Comprehensive documentation for DI patterns
  - Support for decorator pattern with keyed services

- Added `Email` and `EmailVerified` claims to `AuthSession` for external authentication flows (#29, 5db9dba)

- Added `PathString` property to `UriBuilder` for ASP.NET Core compatibility (e5bb347)

- Grant type discovery infrastructure (#33, 19d4b29)

### 🛠️ Improvements

- **Protocol Buffer Serialization**:
  - Implemented protobuf serialization for all OIDC storage types via `ProtobufSerializer`
  - 8 protobuf message definitions with bidirectional mapping
  - `ProtoMapper` utility class with shared extension methods for mapping
  - Uses Google well-known types (Timestamp, Duration, Struct, Value, ListValue) for time and JSON values
  - Zero-serialization conversion through `JsonNodeExtensions` for direct C# ↔ protobuf mapping
  - Eliminated JSON string encoding overhead in `RequestedClaims` and `AuthSession` storage
  - Type preservation for whole numbers during round-trip conversion (42.0 → int, not double)
  - Significantly smaller serialized size compared to JSON (typically 40-60% reduction)
  - 76 comprehensive tests (18 serialization + 20 mapper + 38 JsonNodeExtensions tests)
  - Now default serializer - JSON available through `IBinarySerializer` abstraction for compatibility

- **Code Quality**:
  - Fixed all 45+ nullability warnings for improved type safety (773785a)
  - Migrated to primary constructor syntax for cleaner code (4953845)
  - Improved UriBuilder code quality and documentation (30c9ccf)
  - Simplified string builder initialization in Sanitized class (45ced19)
  - Use `replaceAll` instead of `replace` in checkSession.html (abc6a25)

- **Testing**:
  - Added comprehensive test suite with 834 tests, increasing total number of tests to 1677 (all passing)
  - OAuth 2.0/OIDC endpoint test coverage (3e356b6)
  - Resource validation and dynamic client management tests (4597ca6)
  - UriBuilder comprehensive test coverage (0f9c359)
  - Licensing test suite with bug fixes (36016b1)
  - Fixed unit test mocking for extension methods (6f57a20)
  - Added comprehensive mTLS test suite with 102 tests for RFC 8705 compliance
    - TlsClientAuthenticatorTests: Self-signed certificate authentication (19 tests)
    - TlsClientAuthValidatorTests: Client registration validation (7 tests)
    - CertificateForwardingExtensionsTests: Reverse proxy certificate forwarding (17 tests)
    - DiscoveryControllerMtlsTests: mTLS endpoint alias auto-computation (10 tests)

- **Configuration**:
  - Moved `ExcludeFromCodeCoverage` attribute to project-level configuration (6bc1ba8)
  - Cleaner test projects without scattered assembly attributes

### 🐛 Bug Fixes

- Fixed ECDSA certificate support in `JsonWebKeyExtensions.ToJsonWebKey()` method
  - Method was hardcoded to use RSA algorithm for all certificates
  - Now properly detects and handles both RSA and ECDSA certificates
  - Extracts public/private keys directly using `GetECDsaPublicKey()` / `GetRSAPublicKey()`
- Handle relative URIs without leading slash in UriBuilder (a4cb16c)
- Omit default ports (80 for HTTP, 443 for HTTPS) in UriBuilder output (8fa3a9d)
- Store JWT claims in principal for proper cookie event access (#32, 69e593c)
- Resolve SignOut cookie issues with explicit authentication scheme (#31, a72a909)

### 📝 Documentation

- Extracted URI resolution logic to shared extension method with improved docs (4d328fd)
- Enhanced UriBuilder documentation (30c9ccf)
- Comprehensive DI documentation (#30, 63c40aa)

## [1.6.0] - 2024-08-14

### 🚀 Features

- **Authentication Method References (AMR)**: Added comprehensive support for Authentication Method Reference values in authentication sessions
- **Enhanced Session Tracking**: Improved `AuthSession` authentication methods tracking capabilities

### 🚀 Performance

- **Base32 Encoding Optimization**: Significantly improved performance of Base32 encoding operations, enhancing overall system throughput for token generation and validation processes

## [1.5] - 2024-06-25

### 🚀 Features

- **Multi-value Claim Support**: Added support for claims with multiple values
- **CIBA Infrastructure**: Added stub for Client-Initiated Backchannel Authentication (CIBA) `IUserDeviceAuthorizationHandler` interface

### 🛠️ Fixes

- Fixed routing-template resolution

## [1.4] - 2024-04-09

### 🚀 Features

- **Dynamic Route Resolution**: Configuration-driven route resolution in controller attributes for improved flexibility

## [1.3.1] - 2023-12-03

### 🛠️ Fixes

- Added validation for the `request_uri` parameter in authorization requests

## [1.3.0.1] - 2023-11-28

### 🛠️ Fixes

- Resolved issues with Dependency Injection (DI) setup for Pushed Authorization Requests (PAR)

## [1.3.0] - 2023-11-13

### 🚀 Features

- **Full .NET 9 Support**: Added comprehensive support for .NET 9

## [1.2.0.1] - 2023-10-16

### 🔒 Security

- Fixed Denial of Service vulnerability in cryptography libraries

## [1.2.0] - 2023-10-11

### 🚀 Features

- **Client-Initiated Backchannel Authentication (CIBA)**: Added full support for CIBA specification

## [1.1.0] - 2023-07-09

### 🚀 Features

- **Resource Indicators**: Added support for Resource Indicators (RFC 8707)

### 🛠️ Fixes

- Fixed issuer parameter return from Authorization endpoint

## [1.0.100] - 2023-05-03

### 🚀 Initial Release

Comprehensive initial release with support for:

- **OpenID Connect Core**: Full OIDC core specification implementation
- **OpenID Connect Discovery**: Automatic discovery endpoint support
- **OAuth 2.0 Authorization Framework**: Complete OAuth 2.0 implementation
- **Dynamic Client Registration**: Runtime client registration capabilities
- **Session Management**: Comprehensive session management features
- **Multiple Logout Methods**: Support for various logout flows
- **Pairwise Identifiers**: Privacy-enhanced user identification

---

[2.0]: https://github.com/Abblix/Oidc.Server/compare/v1.6.0...v2.0
[1.6.0]: https://github.com/Abblix/Oidc.Server/compare/v1.5...v1.6.0
[1.5]: https://github.com/Abblix/Oidc.Server/compare/v1.4...v1.5
[1.4]: https://github.com/Abblix/Oidc.Server/compare/v1.3.1...v1.4
[1.3.1]: https://github.com/Abblix/Oidc.Server/compare/v1.3.0.1...v1.3.1
[1.3.0.1]: https://github.com/Abblix/Oidc.Server/compare/v1.3.0...v1.3.0.1
[1.3.0]: https://github.com/Abblix/Oidc.Server/compare/v1.2.0.1...v1.3.0
[1.2.0.1]: https://github.com/Abblix/Oidc.Server/compare/v1.2.0...v1.2.0.1
[1.2.0]: https://github.com/Abblix/Oidc.Server/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Abblix/Oidc.Server/compare/v1.0.100...v1.1.0
[1.0.100]: https://github.com/Abblix/Oidc.Server/releases/tag/v1.0.100
