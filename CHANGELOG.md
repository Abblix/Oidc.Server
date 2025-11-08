# Changelog

All notable changes to Abblix OIDC Server will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-11-XX

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

### 🔒 Security

- Enhanced SSRF (Server-Side Request Forgery) protection with multi-layered security approach (498253c)
  - Added DNS resolution validation before HTTP requests
  - Implemented IP-based blocking for private network ranges
  - Added comprehensive logging for security events
  - Note: TOCTOU vulnerability exists between DNS validation and HTTP request

- Hardened GitHub Actions workflow against supply chain attacks (f96372e)
  - Pinned all GitHub Actions to commit SHA instead of mutable version tags
  - Secured secret handling with environment variables instead of inline expansion

- Added explicit `AttributeUsage` to validation attributes (ac61f96)

### ✨ Features

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

- **Configuration**:
  - Moved `ExcludeFromCodeCoverage` attribute to project-level configuration (6bc1ba8)
  - Cleaner test projects without scattered assembly attributes

### 🐛 Bug Fixes

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

## [1.5.0] - 2024-06-25

### 🚀 Features

- **Multi-value Claim Support**: Added support for claims with multiple values
- **CIBA Infrastructure**: Added stub for Client-Initiated Backchannel Authentication (CIBA) `IUserDeviceAuthorizationHandler` interface

### 🛠️ Fixes

- Fixed routing-template resolution

## [1.4.0] - 2024-04-09

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

[2.0.0]: https://github.com/Abblix/Oidc.Server/compare/v1.6.0...v2.0.0
[1.6.0]: https://github.com/Abblix/Oidc.Server/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/Abblix/Oidc.Server/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/Abblix/Oidc.Server/compare/v1.3.1...v1.4.0
[1.3.1]: https://github.com/Abblix/Oidc.Server/compare/v1.3.0.1...v1.3.1
[1.3.0.1]: https://github.com/Abblix/Oidc.Server/compare/v1.3.0...v1.3.0.1
[1.3.0]: https://github.com/Abblix/Oidc.Server/compare/v1.2.0.1...v1.3.0
[1.2.0.1]: https://github.com/Abblix/Oidc.Server/compare/v1.2.0...v1.2.0.1
[1.2.0]: https://github.com/Abblix/Oidc.Server/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Abblix/Oidc.Server/compare/v1.0.100...v1.1.0
[1.0.100]: https://github.com/Abblix/Oidc.Server/releases/tag/v1.0.100
