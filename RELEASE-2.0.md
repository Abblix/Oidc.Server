# What's New in Abblix OIDC Server 2.0.0

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

**Key Highlights:**
- Complete migration to Result pattern for type-safe error handling
- .NET 10 support with removal of EOL frameworks
- Enhanced SSRF protection with multi-layered security
- Comprehensive test suite (50,000+ lines of new tests)
- RFC 7592 dynamic client registration compliance
- Client credentials JWT authentication (client_secret_jwt)
- Modern C# 12 features throughout codebase

## Breaking Changes

### .NET Target Framework Changes

**Removed Support:**
- .NET 6.0 (reached end-of-life November 2024)
- .NET 7.0 (reached end-of-life May 2024)

**Supported Versions:**
- .NET 8.0 (LTS - supported until November 2026)
- .NET 9.0 (current)
- .NET 10.0 (preview support)

**Migration Impact:** Projects targeting .NET 6 or 7 must upgrade to .NET 8 (LTS) or later.

### Result Pattern Migration

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

### Deprecated IActionContextAccessor Removal

Migrated from deprecated `IActionContextAccessor` to `IHttpContextAccessor` throughout the MVC layer. Code relying on `IActionContextAccessor` must be updated.

### OidcEndpoints Enum Changes

- `OidcEndpoints.Register` renamed to `OidcEndpoints.RegisterClient` for clarity
- Fixed enum flag values to prevent conflicts and ensure proper bitwise operations

### Client Secret Authentication Changes

`ClientSecret` class refactored to remove duplicate `Value` property - now uses inherited property from base type.

## New Features

### RFC 7592 Dynamic Client Registration

Full compliance with RFC 7592 OAuth 2.0 Dynamic Client Registration Management Protocol:

```csharp
services.AddRegistrationAccessTokenService();
```

**Features:**
- Registration access token generation and validation
- Client credential factory for automated client_id/client_secret generation
- Read, update, and delete operations for registered clients
- Token-based access control for client management operations

**New Interfaces:**
- `IRegistrationAccessTokenService` - Token lifecycle management
- `IClientCredentialFactory` - Automated credential generation
- Enhanced `IRegisterClientHandler` with access token support

### Client Credentials JWT Authentication (client_secret_jwt)

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

### SSRF Protection Enhancement

Multi-layered Server-Side Request Forgery protection:

```csharp
services.AddSecureHttpFetcher(options =>
{
    options.MaxContentLength = 10_485_760; // 10 MB
    options.AllowedSchemes = new[] { "https" };
    options.Timeout = TimeSpan.FromSeconds(30);
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

### Endpoint Configuration System

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

### Grant Type Discovery

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

### Enhanced Authentication Session

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

### HTTP Response Headers

New constants for cache control per OIDC specification:

```csharp
public static class HttpResponseHeaders
{
    public const string CacheControl = "Cache-Control";
    public const string Pragma = "Pragma";
    public const string NoCacheDirective = "no-cache, no-store";
    public const string NoStoreDirective = "no-store";
}
```

Token responses now include proper cache control headers to prevent caching of sensitive data.

## Security Enhancements

### GitHub Actions Workflow Hardening

Addressed SonarQube security findings:

```yaml
# Before: Using mutable tags
- uses: actions/checkout@v4

# After: Using immutable SHA hashes
- uses: actions/checkout@08eba0b2dc3465fa44c19e95cfc5adef7493f61f # v4.3.0
```

**Improvements:**
- All actions pinned to commit SHA hashes
- Prevents supply chain attacks through tag manipulation
- Secrets moved to environment variables
- Updated all actions to latest secure versions

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

### Licensing System Enhancement

Comprehensive test coverage for license validation:

```csharp
[Test]
public async Task LicenseChecker_WithExpiredLicense_ThrowsException()
{
    // 541 lines of license validation tests
    // Covers all edge cases and security scenarios
}
```

## Enhancements

### Dependency Injection Improvements

**Enhanced Documentation:**
- Comprehensive XML documentation for all DI extensions
- Detailed remarks sections with usage examples
- Consistent parameter descriptions
- Better IntelliSense experience

**Code Simplification:**
- Removed unnecessary PrivateAssets from project references
- Simplified .csproj dependency declarations
- Better separation of concerns

### Session Management Fixes

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

Modernized to C# 12 collection expressions:

```csharp
// Before
Array.Empty<string>()
new[] { "value1", "value2" }

// After
[]
["value1", "value2"]
```

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

Improved MVC model compliance with specifications:
- Corrected parameter naming conventions
- Fixed required/optional parameter handling
- Enhanced validation attribute accuracy

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

### Type-Safe JSON Web Key Hierarchy

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

### Code Quality Improvements

**SonarQube Findings Addressed:**
- S4136: Method overloads grouped together
- S2259: Null pointer dereference prevention
- S7688: Bash script safety improvements
- Improved polymorphism usage
- Removed redundant code constructs

**Documentation:**
- Simplified verbose XML documentation
- Consistent doc comment patterns
- Reduced "async task" verbosity

**Code Style:**
- Normalized line endings to CRLF for Windows
- Applied consistent formatting
- Removed regions (anti-pattern)
- Extracted magic numbers to constants

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

Added **50,000+ lines** of comprehensive unit tests covering all major subsystems:

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

### Step 1: Update Target Framework

Update your `.csproj` files:

```xml
<!-- Before -->
<TargetFrameworks>net6.0;net7.0;net8.0</TargetFrameworks>

<!-- After -->
<TargetFrameworks>net8.0;net9.0</TargetFrameworks>
```

### Step 2: Update NuGet Packages

```bash
dotnet add package Abblix.Oidc.Server --version 2.0.0
dotnet add package Abblix.Oidc.Server.Mvc --version 2.0.0
dotnet add package Abblix.Jwt --version 2.0.0
```

### Step 3: Migrate to Result Pattern

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

### Step 4: Update Response Formatter Signatures

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

### Step 5: Update Enum References

```csharp
// Before
OidcEndpoints.Register

// After
OidcEndpoints.RegisterClient
```

### Step 6: Migrate from IActionContextAccessor

```csharp
// Before
public class MyService
{
    public MyService(IActionContextAccessor accessor) { }
}

// After
public class MyService
{
    public MyService(IHttpContextAccessor accessor) { }
}
```

### Step 7: Update Custom Validators (if any)

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

### Step 8: Enable SSRF Protection (Recommended)

```csharp
services.AddSecureHttpFetcher(options =>
{
    options.MaxContentLength = 10_485_760; // 10 MB
    options.AllowedSchemes = new[] { "https" };
    options.BlockPrivateNetworks = true;
    options.Timeout = TimeSpan.FromSeconds(30);
});
```

### Step 9: Configure Endpoint Enabling (Optional)

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

### Step 10: Update Client Authentication (if using custom)

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
- Added .NET 10 preview support
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
