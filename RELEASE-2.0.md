# What's New in Abblix OIDC Server 2.0

## Table of Contents
- [Overview](#overview)
- [Breaking Changes](#breaking-changes)
- [New Features](#new-features)
- [Security Enhancements](#security-enhancements)
- [Enhancements](#enhancements)
- [Bug Fixes](#bug-fixes)
- [Refactoring & Code Quality](#refactoring--code-quality)
- [Testing](#testing)
- [Migration Guide](#migration-guide)
- [Statistics](#statistics)

## Overview

Version 2.0.0 represents a major evolution of Abblix OIDC Server with significant architectural improvements, enhanced security, comprehensive test coverage, and modernized codebase. This release introduces breaking changes while delivering substantial improvements in code quality, maintainability, and OAuth 2.0/OpenID Connect compliance.

**Why This Release Matters:**

Version 2.0 addresses critical technical debt while adding features that make Abblix OIDC Server more secure, reliable, and maintainable. The Result pattern migration eliminates an entire class of runtime errors by making success and failure paths explicit at compile time. Enhanced security protections guard against modern attack vectors that could compromise your identity infrastructure. Most importantly, 50,000+ lines of new tests provide confidence that the server behaves correctly under all conditions.

**Key Highlights:**
- **Result pattern migration** - Compiler-enforced error handling prevents missed edge cases
- **.NET 10 support** - Stay current with the latest framework innovations while dropping obsolete versions
- **Multi-layered SSRF protection** - Defend against server-side request forgery attacks targeting your infrastructure
- **50,000+ lines of tests** - Comprehensive coverage validates correct behavior across all OAuth 2.0 and OIDC flows
- **RFC 7592 full compliance** - Dynamic client registration enables automated client onboarding
- **client_secret_jwt authentication** - Standards-compliant JWT-based client authentication
- **Modern C# 12 features** - Reduced boilerplate and improved code clarity throughout

## Breaking Changes

### .NET Target Framework Changes

**What Changed:**

Support for .NET 6.0 and 7.0 has been removed. These framework versions reached end-of-life and no longer receive security updates from Microsoft.

**Removed Support:**
- .NET 6.0 (reached end-of-life November 2024)
- .NET 7.0 (reached end-of-life May 2024)

**Supported Versions:**
- .NET 8.0 (LTS - supported until November 2026)
- .NET 9.0 (current)
- .NET 10.0 (preview support)

**Why This Matters:**

Running identity infrastructure on unsupported frameworks creates security risks. Microsoft no longer patches vulnerabilities in .NET 6 and 7, making them dangerous for production authentication systems. By requiring .NET 8 or later, Abblix ensures you benefit from the latest security fixes and performance improvements.

**Migration Impact:** Projects targeting .NET 6 or 7 must upgrade to .NET 8 (LTS) or later. We recommend .NET 8 for production systems due to its long-term support commitment.

### Result Pattern Migration

**What Changed:**

All response types migrated from inheritance-based patterns to `Result<TSuccess, TFailure>` pattern for improved type safety and functional programming support.

**Previous Pattern:**
```csharp
public abstract record TokenResponse;
public record TokenIssuedResponse : TokenResponse { }
public record TokenErrorResponse : TokenResponse { }
```

**New Pattern:**
```csharp
Result<TokenIssued, TokenError> result = await tokenHandler.HandleAsync(...);

await result.MatchAsync(
    success => /* handle success */,
    error => /* handle error */
);
```

**Why This Matters:**

The old inheritance pattern allowed developers to forget handling error cases, leading to runtime exceptions when unexpected responses occurred. The Result pattern makes success and failure paths explicit in the type system - the compiler forces you to handle both cases. This eliminates an entire category of bugs where error conditions were overlooked during development.

For security-critical identity infrastructure, unhandled error paths can expose sensitive information or create authentication bypass vulnerabilities. The Result pattern ensures every error condition has explicit handling code.

**Changed Response Types:**
- `EndSessionResponse` → `Result<EndSessionSuccess, EndSessionError>`
- `IntrospectionResponse` → `Result<IntrospectionSuccess, IntrospectionError>`
- `RevocationResponse` → `Result<TokenRevoked, RevocationError>`
- `TokenResponse` → `Result<TokenIssued, TokenError>`
- `AuthorizationRequestValidationResult` → `Result<ValidAuthorizationRequest, AuthorizationRequestValidationError>`
- `GrantAuthorizationResult` → `Result<AuthorizedGrant, InvalidGrantResult>`
- `TokenRequestValidationResult` → `Result<ValidTokenRequest, TokenRequestError>`
- And all other endpoint validation/processing results

**Simplified Type Names:**
- `TokenIssuedResponse` → `TokenIssued`
- `TokenErrorResponse` → `TokenError`
- `EndSessionSuccessfulResponse` → `EndSessionSuccess`
- `IntrospectionSuccessResponse` → `IntrospectionSuccess`
- `TokenRevokedResponse` → `TokenRevoked`

### API Interface Changes

**Handler Interfaces Updated:**
```csharp
// Before
Task<TokenResponse> HandleAsync(TokenRequest request);

// After
Task<Result<TokenIssued, TokenError>> HandleAsync(TokenRequest request);
```

All endpoint handlers now return `Result<,>` types:
- `ITokenHandler`
- `IAuthorizationHandler`
- `IEndSessionHandler`
- `IIntrospectionHandler`
- `IRevocationHandler`
- `IUserInfoHandler`
- `IBackChannelAuthenticationHandler`
- `IRegisterClientHandler`
- `IReadClientHandler`
- `IRemoveClientHandler`

### MVC Response Formatter Changes

Response formatters updated to work with Result pattern:

```csharp
// Before
Task FormatResponseAsync(HttpResponse httpResponse, TokenResponse response);

// After
Task FormatResponseAsync(HttpResponse httpResponse, Result<TokenIssued, TokenError> result);
```

### OidcEndpoints Enum Changes

**What Changed:**

- `OidcEndpoints.Register` renamed to `OidcEndpoints.RegisterClient` for clarity
- Fixed enum flag values to prevent conflicts and ensure proper bitwise operations

**Why This Matters:**

The original enum values could overlap when combined using bitwise operations, potentially enabling unintended endpoints or disabling intended ones. This bug could allow unauthorized access to administrative endpoints or accidentally expose functionality that should remain disabled. The corrected flag values ensure that endpoint configurations work exactly as specified, with no unintended side effects.

## New Features

### Client Credentials JWT Authentication (client_secret_jwt)

**What It Does:**

Implemented `client_secret_jwt` authentication method per OpenID Connect Core specification:

```csharp
public class ClientSecretJwtAuthenticator : JwtAssertionAuthenticatorBase
{
    // Validates JWT assertions signed with client_secret
    // Supports HS256, HS384, HS512 algorithms
}
```

**Features:**
- HMAC-based JWT signature validation
- Configurable clock skew tolerance
- Comprehensive audience and issuer validation
- Integration with existing client authentication flow

**Why This Matters:**

Traditional client authentication sends secrets in HTTP headers or request bodies, creating multiple opportunities for interception. The `client_secret_jwt` method packages client credentials in a cryptographically signed JWT with expiration, preventing replay attacks and providing non-repudiation. This authentication method is increasingly required by regulatory frameworks and enterprise security policies.

**Real-World Impact:**

Financial institutions and healthcare providers can now integrate applications that require JWT-based client authentication, expanding Abblix's applicability to highly regulated industries. The built-in clock skew tolerance handles real-world timing issues without compromising security.

### SSRF Protection Enhancement

**What It Does:**

Multi-layered Server-Side Request Forgery protection:

```csharp
services.AddSecureHttpFetch(options =>
{
    options.MaxResponseSizeBytes = 10_485_760; // 10 MB
    options.RequestTimeout = TimeSpan.FromSeconds(30);
    options.AllowedSchemes = new[] { "https" }; // HTTPS only
    options.BlockPrivateNetworks = true; // Block private IPs (default)
});
```

**New Components:**
- `SecureHttpFetcher` - Secure HTTP client with validation
- `SsrfValidatingHttpMessageHandler` - HTTP handler with SSRF checks
- `SecureHttpFetchOptions` - Configuration for security policies

**Protection Features:**
- Blocks private IP ranges (RFC 1918, RFC 4193)
- Prevents localhost/loopback access
- DNS rebinding attack prevention
- Response size limits
- Content-Type validation
- HTTPS enforcement option
- Request timeout controls

**Where It's Used:**

Oidc.Server uses the secure HTTP fetch feature for both request object fetching (via `request_uri` parameter) and sector identifier URI validation checks during dynamic client registration. This generalizes the security approach across all external URI fetching operations, making the implementation consistent and secure by default. The centralized protection layer allows you to enforce additional security checks and policies in one place, rather than duplicating validation logic across multiple components.

**Why This Matters:**

SSRF attacks allow malicious actors to trick your server into making requests to internal resources - database servers, cloud metadata endpoints, or internal APIs that should never be accessible from the internet. A successful SSRF attack against an identity provider could expose environment variables containing database credentials, retrieve cloud instance metadata with elevated permissions, or scan internal networks for vulnerabilities.

**Real-World Impact:**

The multi-layered protection prevents attackers from exploiting OpenID Connect's dynamic discovery features to probe your internal infrastructure. DNS rebinding protection ensures that even if attackers control DNS, they cannot redirect requests to internal IPs after initial validation. Size limits prevent resource exhaustion attacks that could bring down your authentication service.

### Endpoint Configuration System

**What It Does:**

New attribute-based endpoint enabling/disabling:

```csharp
[EnabledBy(OidcEndpoints.Token)]
public class TokenController : ControllerBase
{
    [EnabledBy(OidcEndpoints.Token)]
    public Task<IActionResult> Token([FromBody] TokenRequest request)
    {
        // Automatically disabled if OidcEndpoints.Token not in OidcOptions.Endpoints
    }
}
```

**Components:**
- `EnabledByAttribute` - Declarative endpoint control
- `EnabledByConvention` - Convention-based registration
- Automatic route filtering based on `OidcOptions.Endpoints` configuration

**Why This Matters:**

Different deployment scenarios require different OAuth 2.0 endpoints. A mobile app backend might only need token introspection, while a full identity provider needs all endpoints. Previously, disabled endpoints still existed in routing tables and could potentially be accessed through misconfigurations. The new system completely removes disabled endpoints from the application, reducing attack surface and preventing accidental exposure.

**Real-World Impact:**

Security audits can now verify that unused endpoints truly don't exist rather than trusting configuration. This declarative approach makes deployment configurations self-documenting - reading the code clearly shows which endpoints are available in each configuration. Microservice architectures can deploy minimal endpoint sets, reducing memory footprint and improving startup time.

### Grant Type Discovery

**What It Does:**

Dynamic grant type discovery infrastructure:

```csharp
public interface IGrantTypeInformer
{
    IEnumerable<string> GetSupportedGrantTypes();
}
```

**Features:**
- Authorization handlers automatically report implicit grant support
- Discovery endpoint aggregates grant types from all registered handlers
- Supports dynamic grant type registration
- Enables accurate OpenID Provider metadata

**Why This Matters:**

OAuth 2.0 clients rely on the discovery endpoint to learn which grant types an authorization server supports. Hardcoded grant type lists become outdated when custom grant handlers are added, causing client integration failures. Dynamic discovery ensures the metadata accurately reflects runtime capabilities, including custom grant types.

**Real-World Impact:**

When you add a custom grant type handler, clients automatically discover it through the standard OpenID Connect discovery mechanism. This eliminates manual documentation updates and prevents client-server mismatches that cause authentication failures. Third-party OAuth 2.0 client libraries can correctly configure themselves based on accurate server metadata.

### Enhanced Authentication Session

**What It Does:**

Extended `AuthSession` with external authentication support:

```csharp
public record AuthSession
{
    public string? Email { get; init; }
    public bool? EmailVerified { get; init; }
    // ... existing properties
}
```

**Benefits:**
- Preserves exact email from external providers (Google, Microsoft, etc.)
- Maintains email verification status from authentication method
- Improved ID token accuracy for federated authentication
- Better support for email verification challenges

**Why This Matters:**

When users authenticate through Google or Microsoft, those providers verify email ownership. Previously, Abblix couldn't preserve this verification status when issuing tokens, potentially requiring redundant email verification. This creates friction in user onboarding and degrades the user experience.

**Real-World Impact:**

Applications implementing "Sign in with Google" can now trust the email_verified claim in ID tokens, skipping unnecessary email verification flows. This reduces user friction while maintaining security - users verified by trusted providers don't need to verify again with your application. The exact email preservation prevents normalization issues where uppercase/lowercase differences could create duplicate accounts.

### Keyed Service Decoration

Enhanced dependency injection with keyed service support:

```csharp
services.AddKeyedScoped<IService, Service>("key");
services.DecorateKeyed<IService>("key", (inner, sp) => new Decorator(inner));
```

**Features:**
- `DecorateKeyed` extension method for keyed services
- Full parameter validation
- Support for `(IServiceProvider, object key)` factory patterns
- Comprehensive XML documentation

### UriBuilder Enhancements

Enhanced URI building with ASP.NET Core integration:

```csharp
var builder = new UriBuilder("/callback");
builder.AppendQuery("code", authCode);
Uri uri = builder.Uri; // Handles relative and absolute URIs
```

**Features:**
- Relative URI support (previously required absolute URIs)
- `PathString` property for ASP.NET Core compatibility
- Automatic handling of URI kind (absolute vs relative)
- Improved redirect URI construction

## Security Enhancements

### SSRF Validation Enhancements

```csharp
public class SsrfValidatingHttpMessageHandler : HttpClientHandler
{
    // Multi-layered SSRF protection:
    // 1. Blocks private IP ranges before DNS resolution
    // 2. Validates resolved IPs after DNS lookup
    // 3. Prevents DNS rebinding attacks
    // 4. Enforces HTTPS when configured
}
```

**Protected Ranges:**
- 127.0.0.0/8 (Loopback)
- 10.0.0.0/8 (Private)
- 172.16.0.0/12 (Private)
- 192.168.0.0/16 (Private)
- ::1 (IPv6 loopback)
- fc00::/7 (IPv6 unique local)
- fe80::/10 (IPv6 link-local)

## Enhancements

### Dependency Injection Improvements

**What Changed:**

**Enhanced Documentation:**
- Comprehensive XML documentation for all DI extensions
- Detailed remarks sections with usage examples
- Consistent parameter descriptions
- Better IntelliSense experience

**Code Simplification:**
- Removed unnecessary PrivateAssets from project references
- Simplified .csproj dependency declarations
- Better separation of concerns

**Why This Matters:**

Dependency injection configuration is where most integration errors occur. Developers extending Abblix need clear documentation at their fingertips. Enhanced XML documentation means IntelliSense provides complete guidance without leaving the IDE, reducing trial-and-error during integration. Simplified project references prevent dependency conflicts that cause runtime failures.

**Real-World Impact:**

Integration time decreases significantly when developers can configure services correctly on the first try. Clear documentation prevents common mistakes like registering services with incorrect lifetimes or missing required dependencies. Project reference simplification reduces build times and prevents frustrating "Could not load assembly" errors in production.

### Session Management Fixes

**What Changed:**

Fixed critical session accumulation issue with distributed cache:

```csharp
// Critical claims now stored in ClaimsPrincipal instead of AuthenticationProperties
// This ensures they're accessible in cookie authentication events
claims.Add(new Claim(JwtClaimTypes.SessionId, sessionId));
claims.Add(new Claim(JwtClaimTypes.AuthenticationTime, authTime));
```

**Benefits:**
- Proper session cleanup in distributed cache scenarios
- Accessible claims during SignOut events
- Prevents session accumulation
- Compatible with `DistributedCacheTicketStore`

**Why This Matters:**

In distributed deployments using Redis or SQL Server for session storage, sessions accumulated indefinitely because SignOut events couldn't access session identifiers stored in AuthenticationProperties. This memory leak could exhaust cache storage, causing authentication failures for all users. In production environments with thousands of daily authentications, uncleaned sessions could fill gigabytes of cache storage within weeks.

**Real-World Impact:**

Production systems can now run indefinitely without cache storage exhaustion. Distributed deployments across multiple servers properly clean up sessions regardless of which server handles sign-out. This fix is essential for Kubernetes deployments and load-balanced configurations where session cleanup must work consistently across all nodes.

### Cookie Authentication Improvements

```csharp
public class AuthenticationSchemeAdapter
{
    public AuthenticationSchemeAdapter(
        IAuthenticationService authService,
        string authenticationScheme = CookieAuthenticationDefaults.AuthenticationScheme)
    {
        // Explicit authentication scheme support
        // Fixes multi-scheme scenarios
    }
}
```

### URI Resolution

Extracted duplicate URI resolution logic to shared extension:

```csharp
public static Uri ToAbsoluteUri(this HttpRequest request, string path)
{
    // Handles both relative and app-relative paths (~/...)
    // Centralizes conversion to absolute URIs
}
```

### User Info Provider Enhancement

Updated interface to accept `AuthSession` for better context:

```csharp
Task<UserInfo> GetUserInfoAsync(AuthSession authSession);
// Instead of: Task<UserInfo> GetUserInfoAsync(string subject);
```

Enables access to authentication method, email from external providers, and other session context.

### Collection Expressions

**What Changed:**

Modernized to C# 12 collection expressions:

```csharp
// Before
Array.Empty<string>()
new[] { "value1", "value2" }

// After
[]
["value1", "value2"]
```

**Why This Matters:**

Collection expressions are more than syntactic sugar - they enable compiler optimizations and reduce cognitive load. The concise syntax makes code intention clearer, reducing bugs from verbose initialization patterns. The compiler can optimize collection expressions more aggressively than traditional array initialization.

**Real-World Impact:**

Throughout the codebase, collection initialization patterns are now consistent and readable. Code reviews focus on logic rather than boilerplate syntax. The modernized syntax aligns with current C# best practices, making the codebase more accessible to developers familiar with modern C#.

### Client Cache Expiration

Added per-client TTL control for dynamic registration:

```csharp
public record ClientInfo
{
    public TimeSpan? ExpiresAfter { get; init; }
    // Enables pseudo-sliding expiration in distributed cache
}
```

## Bug Fixes

### Fixed OAuth 2.0/OIDC Specification Compliance

**What Changed:**

Improved MVC model compliance with specifications:
- Corrected parameter naming conventions
- Fixed required/optional parameter handling
- Enhanced validation attribute accuracy

**Why This Matters:**

OAuth 2.0 and OpenID Connect specifications define exact parameter names and validation rules. Deviations cause integration failures with standards-compliant clients. Parameter naming mismatches prevent clients from sending requests correctly, while incorrect validation can reject valid requests or accept invalid ones, creating both usability and security issues.

**Real-World Impact:**

Third-party OAuth 2.0 client libraries that strictly follow specifications now integrate seamlessly without workarounds. Certification test suites pass without custom modifications. This compliance ensures Abblix works with the entire ecosystem of standards-compliant OAuth 2.0 and OpenID Connect tools and libraries.

### Fixed OidcEndpoints Enum Flag Values

Corrected bitwise flag values to prevent conflicts:

```csharp
public enum OidcEndpoints
{
    None = 0,
    Authorization = 1,
    Token = 2,
    UserInfo = 4,
    // ... properly spaced flag values
}
```

### Fixed UriBuilder Edge Cases

- Handle relative URIs without leading slash
- Omit default ports (80 for HTTP, 443 for HTTPS)
- Proper fragment handling
- PathString integration fixes

### Fixed AttributeUsage Declarations

Added explicit `AttributeUsage` to validation attributes:

```csharp
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Parameter)]
public class ElementsRequiredAttribute : ValidationAttribute
```

### Fixed Nullability Warnings

Removed unused test projects and resolved nullability warnings across codebase.

### Fixed JSON Deserialization Edge Cases

Robust handling of claim arrays in both JSON and plain text formats:

```csharp
public static bool TryGetStringList(this ClaimsPrincipal principal, string claimType, out string[] values)
{
    // Handles both ["value1", "value2"] and "plain text" formats
}
```

### Fixed checkSession.html

Replaced deprecated `String.replace()` with `String.replaceAll()` for better browser compatibility.

## Refactoring & Code Quality

### Primary Constructors (C# 12)

Migrated entire codebase to primary constructor syntax:

```csharp
// Before
public class TokenHandler
{
    private readonly ITokenService _tokenService;

    public TokenHandler(ITokenService tokenService)
    {
        _tokenService = tokenService;
    }
}

// After
public class TokenHandler(ITokenService tokenService)
{
    // ~900 lines of boilerplate removed across codebase
}
```

**Impact:** 74 classes refactored, significant reduction in boilerplate code.

**Why This Matters:**

Primary constructors eliminate repetitive field declarations and assignment code that added no value but consumed screen space and mental energy. Removing 900 lines of boilerplate means less code to maintain, fewer merge conflicts, and clearer focus on actual business logic. The pattern also encourages immutability by making captured constructor parameters readonly by default.

**Real-World Impact:**

Code reviews become faster because reviewers can immediately see class dependencies without scrolling past constructor boilerplate. New team members can understand class structure more quickly. IDE navigation improves because there's less clutter between important methods. The reduced line count also speeds up compilation and IDE analysis.

### Type-Safe JSON Web Key Hierarchy

**What Changed:**

Established strongly-typed JWK hierarchy with RFC compliance:

```csharp
public abstract record JsonWebKey
{
    public abstract string KeyType { get; }
    // ... common properties
}

public record RsaJsonWebKey : JsonWebKey
{
    public override string KeyType => JsonWebKeyTypes.Rsa;
    public string N { get; init; } // Modulus
    public string E { get; init; } // Exponent
    // ... RSA-specific properties
}

public record EllipticCurveJsonWebKey : JsonWebKey
{
    public override string KeyType => JsonWebKeyTypes.EllipticCurve;
    public string Crv { get; init; } // Curve
    public string X { get; init; }
    public string Y { get; init; }
    // ... EC-specific properties
}

public record OctetJsonWebKey : JsonWebKey
{
    public override string KeyType => JsonWebKeyTypes.Octet;
    public string K { get; init; } // Key value
}
```

**Benefits:**
- Type safety for cryptographic operations
- Better IDE support and IntelliSense
- Compile-time validation of JWK structure
- Improved JSON serialization/deserialization

**New Components:**
- `JsonWebKeyConverter` - Custom JSON converter
- `JsonWebKeyPropertyNames` - RFC 7517 property constants
- `EncryptionAlgorithms` - Algorithm identifier constants

**Why This Matters:**

Cryptographic key handling is error-prone - using the wrong key type or accessing non-existent properties can compromise security. The previous loosely-typed approach allowed runtime errors where RSA-specific code accidentally processed elliptic curve keys. Strongly-typed records make these errors impossible, catching mismatches at compile time.

**Real-World Impact:**

When implementing custom JWT validation or key rotation logic, the type system prevents you from accessing RSA-specific properties on an elliptic curve key. IntelliSense shows only the properties valid for each key type, eliminating documentation lookups. JSON serialization automatically handles polymorphic key types correctly, preventing subtle bugs in JWKS endpoint responses.

### JWT Validation Pattern Migration

Migrated from inheritance to Result pattern:

```csharp
// Before
public abstract record JwtValidationResult;
public record ValidJsonWebToken : JwtValidationResult;
public record JwtValidationError : JwtValidationResult;

// After
Result<JsonWebToken, JwtValidationError> result = await validator.ValidateAsync(token);
```

### Sanitized Security Pattern

Refactored to static factory pattern:

```csharp
// Before
var sanitized = new Sanitized(userInput);

// After
var sanitized = Sanitized.Value(userInput);
```

Strengthens log injection prevention with clearer API semantics.

### HttpClientHandler Encapsulation

Encapsulated configuration in `SsrfValidatingHttpMessageHandler`:

```csharp
public class SsrfValidatingHttpMessageHandler : HttpClientHandler
{
    public SsrfValidatingHttpMessageHandler()
    {
        // Centralized configuration
        ServerCertificateCustomValidationCallback = ...;
        SslProtocols = ...;
        // SSRF validation logic
    }
}
```

### ExcludeFromCodeCoverage Configuration

Moved to project-level configuration for consistency:

```xml
<ItemGroup>
  <AssemblyAttribute Include="System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage" />
</ItemGroup>
```

## Testing

### Comprehensive Test Suite Addition

**What Changed:**

Added **50,000+ lines** of comprehensive unit tests covering all major subsystems.

**Why This Matters:**

Identity infrastructure failures have catastrophic consequences - authentication outages prevent users from accessing any service, while security bugs expose every integrated application. Without comprehensive tests, changes risk breaking critical authentication flows or introducing security vulnerabilities. The 50,000+ lines of tests provide confidence that all OAuth 2.0 and OpenID Connect flows work correctly under normal conditions, error conditions, and edge cases.

**Real-World Impact:**

Teams can now refactor code, upgrade dependencies, and add features with confidence that tests will catch regressions immediately. The comprehensive test coverage enables continuous deployment - automated tests validate every change before it reaches production. This transforms Abblix from "too risky to change" to "safe to evolve," enabling rapid response to security vulnerabilities and feature requests.

**Test Coverage:**

**Endpoint Tests (14,000+ lines):**
- Authorization endpoint validation (1,169 lines)
- Authorization handler logic (353 lines)
- Token endpoint processing (600 lines)
- Token grant handlers (1,562 lines)
- User info endpoint (1,306 lines)
- Introspection endpoint (1,100 lines)
- Revocation endpoint (1,226 lines)
- End session endpoint (1,509 lines)
- Back-channel authentication (2,100+ lines)
- Dynamic client management (3,500+ lines)

**Feature Tests (20,000+ lines):**
- Client authentication (3,400+ lines)
  - Basic authentication (584 lines)
  - POST authentication (550 lines)
  - JWT authentication (467 lines)
  - Private key JWT (531 lines)
  - Composite authenticator (379 lines)
- SSRF protection (693 lines)
- Session management (777 lines)
- Logout notification (2,438 lines)
- Storage services (4,180+ lines)
- Token services (3,384+ lines)
- Hashing service (509 lines)
- Resource management (788 lines)
- Scope management (811 lines)
- URI validation (707 lines)

**JWT & Cryptography Tests (1,900+ lines):**
- JSON Web Token validation (625 lines)
- JWT claims processing (750 lines)
- JWK serialization (551 lines)

**Licensing Tests (3,400+ lines):**
- License checker (188 lines)
- License enforcement (417 lines)
- License loading (660 lines)
- License logger (541 lines)
- License manager (372 lines)
- Aggregation extensions (455 lines)

**Dependency Injection Tests (533 lines):**
- AddAlias functionality (297 lines)
- AddKeyedAlias functionality (236 lines)

**Infrastructure Tests:**
- UriBuilder (comprehensive coverage)
- Endpoint conventions (230 lines)
- Grant type discovery

**Test Quality:**
- Follows AAA (Arrange-Act-Assert) pattern
- Comprehensive edge case coverage
- Theory-based parameterized tests
- Mock-based isolation
- Reflection for private member testing

### Test Infrastructure Improvements

Fixed unit test mocking for extension methods:

```csharp
// Proper setup for extension method mocks
var mockService = new Mock<IService>();
// Comprehensive test helper organization
```

## Migration Guide

### Update Target Framework

Update your `.csproj` files:

```xml
<!-- Before -->
<TargetFrameworks>net6.0;net7.0;net8.0</TargetFrameworks>

<!-- After -->
<TargetFrameworks>net8.0;net9.0;net10.0</TargetFrameworks>
```

### Update NuGet Packages

```bash
dotnet add package Abblix.Oidc.Server --version 2.0.0
dotnet add package Abblix.Oidc.Server.Mvc --version 2.0.0
dotnet add package Abblix.Jwt --version 2.0.0
```

### Migrate to Result Pattern

**Handler Implementations:**

```csharp
// Before
public async Task<TokenResponse> HandleAsync(TokenRequest request)
{
    if (error)
        return new TokenErrorResponse { ... };
    return new TokenIssuedResponse { ... };
}

// After
public async Task<Result<TokenIssued, TokenError>> HandleAsync(TokenRequest request)
{
    if (error)
        return new TokenError { ... };
    return new TokenIssued { ... };
}
```

**Response Handling:**

```csharp
// Before
var response = await handler.HandleAsync(request);
if (response is TokenIssuedResponse success)
{
    // handle success
}
else if (response is TokenErrorResponse error)
{
    // handle error
}

// After
var result = await handler.HandleAsync(request);
await result.MatchAsync(
    success => /* handle TokenIssued */,
    error => /* handle TokenError */
);

// Or using pattern matching
return result switch
{
    { IsSuccess: true } => Ok(result.GetSuccess()),
    { IsFailure: true } => BadRequest(result.GetFailure()),
};
```

### Update Response Formatter Signatures

```csharp
// Before
public class CustomTokenFormatter : ITokenResponseFormatter
{
    public Task FormatResponseAsync(HttpResponse httpResponse, TokenResponse response)
    {
        return response switch
        {
            TokenIssuedResponse success => /* format */,
            TokenErrorResponse error => /* format */,
            _ => throw new ArgumentOutOfRangeException()
        };
    }
}

// After
public class CustomTokenFormatter : ITokenResponseFormatter
{
    public async Task FormatResponseAsync(
        HttpResponse httpResponse,
        Result<TokenIssued, TokenError> result)
    {
        await result.MatchAsync(
            success => /* format TokenIssued */,
            error => /* format TokenError */
        );
    }
}
```

### Update Enum References

```csharp
// Before
OidcEndpoints.Register

// After
OidcEndpoints.RegisterClient
```

### Update Custom Validators (if any)

Validation results now use Result pattern:

```csharp
// Before
public async Task<AuthorizationRequestValidationResult> ValidateAsync(...)
{
    if (invalid)
        return new AuthorizationRequestValidationError(...);
    return new ValidAuthorizationRequest(...);
}

// After
public async Task<Result<ValidAuthorizationRequest, AuthorizationRequestValidationError>> ValidateAsync(...)
{
    if (invalid)
        return new AuthorizationRequestValidationError(...);
    return new ValidAuthorizationRequest(...);
}
```

### Enable SSRF Protection (Recommended)

```csharp
services.AddSecureHttpFetch(options =>
{
    options.MaxResponseSizeBytes = 10_485_760; // 10 MB
    options.RequestTimeout = TimeSpan.FromSeconds(30);
    options.AllowedSchemes = new[] { "https" }; // HTTPS only
    options.BlockPrivateNetworks = true; // Block private IPs (default)
});
```

### Configure Endpoint Enabling (Optional)

The new endpoint configuration system is automatically applied:

```csharp
services.AddOidcServices(options =>
{
    // Only enabled endpoints will have active routes
    options.Endpoints = OidcEndpoints.Authorization |
                       OidcEndpoints.Token |
                       OidcEndpoints.UserInfo;
});
```

### Update Client Authentication (if using custom)

If you implemented custom client authentication:

```csharp
// The IClientAuthenticator interface signature remains the same,
// but consider inheriting from JwtAssertionAuthenticatorBase
// for JWT-based authentication methods
```

## Statistics

**Overall Changes:**
- **531 files changed**
- **57,277 insertions**
- **6,930 deletions**
- **55 commits**
- **Net addition: 50,347 lines**

**Test Coverage:**
- **50,000+ lines of new tests**
- **200+ new test classes**
- **2,000+ test methods**
- Coverage across all major subsystems

**Code Quality:**
- **74 classes** migrated to primary constructors
- **~900 lines** of boilerplate removed
- **92 files** with simplified documentation
- **All SonarQube critical findings** addressed

**Dependencies:**
- Updated to latest .NET 9 packages
- Added .NET 10 LTS support (released November 11, 2025)
- Security patches applied

**Supported Standards:**
- OAuth 2.0 (RFC 6749)
- OpenID Connect Core 1.0
- RFC 7517 (JSON Web Key)
- RFC 7519 (JSON Web Token)
- RFC 7592 (Dynamic Client Registration)
- RFC 7636 (PKCE)
- RFC 8414 (Authorization Server Metadata)
- RFC 9126 (Pushed Authorization Requests)

---

For questions or support, visit [https://oidc.abblix.com](https://oidc.abblix.com) or contact info@abblix.com.
