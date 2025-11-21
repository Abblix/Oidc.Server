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

The old approach used inheritance with abstract base types and concrete success/error subtypes, allowing developers to potentially forget handling error cases.

**New Pattern:**

The Result pattern wraps success and failure in a discriminated union type, forcing explicit handling of both paths through pattern matching or dedicated match methods.

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

All handler interfaces changed from returning abstract response types to returning Result with explicit success and failure generic parameters.

Affected endpoint handlers:
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

Response formatters updated to accept Result types instead of abstract response types, enabling pattern matching on success and failure cases directly in the formatter.

### OidcEndpoints Enum Changes

**What Changed:**

- `OidcEndpoints.Register` renamed to `OidcEndpoints.RegisterClient` for clarity
- Fixed enum flag values to prevent conflicts and ensure proper bitwise operations

**Why This Matters:**

The original enum values could overlap when combined using bitwise operations, potentially enabling unintended endpoints or disabling intended ones. This bug could allow unauthorized access to administrative endpoints or accidentally expose functionality that should remain disabled. The corrected flag values ensure that endpoint configurations work exactly as specified, with no unintended side effects.

### IRequestInfoProvider Interface Changes

**What Changed:**

Added a new property to the request info provider interface that returns the client's IP address. This enables security audit logging to include the source IP address of incoming requests.

**Migration Impact:**

Custom implementations of this interface must add the new property. The built-in ASP.NET Core adapter has been updated to return the remote IP address from the HTTP connection.

### JsonWebTokenHeader Changes

**What Changed:**

Added a property to the JWT header class that exposes the key ID claim, enabling audit logs to record which signing key was used to sign incoming JWT assertions.

## New Features

### CIBA Ping and Push Modes - Complete Delivery Mode Implementation

**What It Enables:**

Version 2.0 completes the Client-Initiated Backchannel Authentication (CIBA) implementation by adding ping mode status notification infrastructure and push mode token delivery, providing all three CIBA delivery modes (poll, ping, and push).

**Key Components:**

- **Long-Polling Support**: Configurable long-polling for token endpoint in poll mode
  - Holds polling requests until authentication completes or timeout expires (default: 30 seconds)
  - Dramatically reduces server load by eliminating rapid repeated polling
  - Cuts latency by returning immediately when authentication completes
  - Optional feature controlled by `BackChannelAuthenticationOptions.UseLongPolling`

- **Status Notification**: `IBackChannelAuthenticationStatusNotifier` interface with `InMemoryBackChannelAuthenticationStatusNotifier` implementation
  - Enables real-time notification when authentication requests complete
  - Powers long-polling functionality without repeatedly querying storage
  - TaskCompletionSource-based async notification mechanism
  - Thread-safe concurrent dictionary for managing multiple pending requests

- **Token Delivery**: `IBackChannelTokenDeliveryService` interface with `HttpBackChannelTokenDeliveryService` implementation
  - Abstraction for delivering tokens in push mode
  - HTTP POST-based delivery to client notification endpoints
  - Secure token transmission with client notification tokens

- **Atomic Cache Operations**: `DistributedCacheExtensions.TryGetAndRemoveAsync()`
  - 4-step last-write-wins protocol prevents race conditions
  - Works across Redis, SQL Server, and in-memory cache implementations
  - Comprehensive test coverage including 100-thread concurrency scenarios

- **Strategy Pattern Refactoring**: Separate grant processors for poll/ping/push modes via keyed DI
  - Eliminates conditional branching in grant handlers
  - Makes adding new delivery modes straightforward
  - Unified `BackChannelAuthenticationRequest` model with required `ExpiresAt`

**Why This Matters:**

CIBA's advanced delivery modes are critical for financial services and IoT scenarios where immediate notification is required when authentication completes.

- **Long-polling** (available in poll mode) holds requests for up to 30 seconds instead of immediately returning "authorization_pending", dramatically reducing both server load and response latency for slow authentication scenarios
- **Ping mode** enables efficient notification by telling clients at their callback endpoint the moment authentication completes, so they know exactly when to request tokens
- **Push mode** goes further by delivering tokens directly to the client notification endpoint, eliminating the need for clients to make a separate token request at all

These delivery modes are essential for real-time authentication scenarios where delays are unacceptable, such as payment authorization, IoT device provisioning, or mobile banking authentication.

### JWT Bearer Grant Type (RFC 7523)

**What It Does:**

Full implementation of JWT Bearer grant type for token exchange scenarios, allowing clients to exchange a JWT assertion from a trusted identity provider for an access token at this authorization server. This grant type is specified in RFC 7523 and enables service-to-service authentication, token exchange between federated identity providers, and cross-domain SSO scenarios.

**Features:**
- **Configuration-Based Setup**: Declarative trusted issuer configuration via `OidcOptions.JwtBearer.TrustedIssuers`
- **Automatic JWKS Fetching**: Default `JwtBearerIssuerProvider` automatically fetches signing keys from configured JWKS URIs
- **RFC 7523 Compliance**: Proper validation of issuer (iss), subject (sub), audience (aud), and expiration (exp) claims
- **Security Hardening**: Multiple attack prevention mechanisms:
  - Algorithm substitution attack prevention with configurable allowed algorithms (defaults to RS/ES/PS only, no HMAC or 'none')
  - Token type (`typ` header) validation to prevent token confusion attacks
  - Maximum JWT age (`MaxJwtAge`) validation with required `iat` claim to prevent stale token reuse
  - Replay protection via `jti` claim tracking with configurable `RequireJti` option
  - Maximum JWT size limit (`MaxJwtSize`) to prevent denial-of-service attacks
  - Scope restriction per trusted issuer via `AllowedScopes` configuration
  - Strict vs permissive audience validation modes via `StrictAudienceValidation` option
- **Enhanced Audit Logging**: Security-critical logging includes client IP address and JWT key ID (`kid`)
- **Extensibility**: `IJwtBearerIssuerProvider` interface allows custom issuer validation strategies

**Why This Matters:**

Federation scenarios are increasingly common in enterprise environments where organizations need to accept tokens from external identity providers while maintaining security controls. The JWT Bearer grant type enables:
- **Service-to-service authentication** with pre-existing trust relationships between organizations
- **Token exchange** between federated identity providers without exposing user credentials
- **Cross-domain SSO** where users authenticated by one organization need access to another's resources

The comprehensive security hardening prevents common JWT-based attacks including algorithm confusion (CVE-2015-9235), token confusion, replay attacks, and denial-of-service through oversized tokens.

**Real-World Impact:**

Organizations can now integrate with external identity providers (Azure AD, Okta, Auth0, Google) using standard JWT Bearer assertions, enabling B2B federation scenarios. The security controls ensure that even if trusted issuers are compromised, the attack surface is limited through algorithm restrictions, age limits, and replay protection.

### Client Credentials JWT Authentication (client_secret_jwt)

**What It Does:**

Implemented client secret JWT authentication method per OpenID Connect Core specification through a dedicated authenticator that validates JWT assertions signed with the client secret, supporting HMAC algorithms HS256, HS384, and HS512.

**Features:**
- HMAC-based JWT signature validation
- Configurable clock skew tolerance
- Comprehensive audience and issuer validation
- Integration with existing client authentication flow

**Why This Matters:**

Traditional client authentication sends secrets in HTTP headers or request bodies, creating multiple opportunities for interception. The `client_secret_jwt` method packages client credentials in a cryptographically signed JWT with expiration, preventing replay attacks and providing non-repudiation. This authentication method is increasingly required by regulatory frameworks and enterprise security policies.

**Real-World Impact:**

Financial institutions and healthcare providers can now integrate applications that require JWT-based client authentication, expanding Abblix's applicability to highly regulated industries. The built-in clock skew tolerance handles real-world timing issues without compromising security.

### Mutual TLS (mTLS) Client Authentication (RFC 8705)

**What It Does:**

Implemented comprehensive RFC 8705 mutual TLS client authentication supporting both self-signed certificates and PKI/certificate authority validation through two specialized authenticators. The self-signed authenticator validates certificate public keys against the client's registered JWKS, supporting both RSA and ECDSA certificates. The metadata-based authenticator validates certificates against registered Subject Distinguished Names and Subject Alternative Name entries including DNS names, URIs, IP addresses, and email addresses.

**Authentication Methods:**
- `self_signed_tls_client_auth` - Public key matching against client JWKS
- `tls_client_auth` - Subject DN and SAN validation against registered metadata

**Features:**
- **Certificate-bound tokens** - Automatic SHA-256 certificate thumbprint injection in confirmation claim for holder-of-key semantics
- **Flexible validation** - Match by Subject Distinguished Name, DNS name, URI, IP address, or email address
- **Proper ASN.1 parsing** - Locale-independent Subject Alternative Name extraction using standard ASN.1 DER decoding
- **RFC 4514 DN normalization** - Binary Distinguished Name comparison for accurate matching
- **Certificate forwarding** - Integration with ASP.NET Core's built-in certificate forwarding middleware for reverse proxy scenarios
- **Discovery support** - Auto-computed mTLS endpoint aliases for RFC 8705 compliance
- **Multi-algorithm support** - RSA and ECDSA certificate validation
- **Registration validation** - Validates mTLS metadata during dynamic client registration

**Certificate Forwarding:**

Applications can leverage ASP.NET Core's built-in certificate forwarding middleware by registering it with a convenience extension method that configures certificate header parsing. The middleware must be added to the pipeline before authentication middleware to properly populate certificate information from reverse proxy headers.

**Why This Matters:**

Mutual TLS provides cryptographic proof of client identity at the transport layer, eliminating password-based authentication vulnerabilities. Certificate-based authentication is:
- **Phishing-resistant** - No credentials to steal or replay
- **Rotation-friendly** - Certificates expire and rotate automatically
- **Hardware-bound** - Can be stored in HSMs or TPMs
- **Compliance-ready** - Required by PSD2, Open Banking, FAPI, and other regulatory frameworks

Traditional client secrets can be intercepted, stolen from code repositories, or leaked through logs. mTLS binds authentication to cryptographic material that never leaves the client's control. Certificate-bound tokens prevent token theft attacks - even if an attacker steals an access token, they can't use it without the matching client certificate.

**Real-World Impact:**

Financial APIs (PSD2, Open Banking), healthcare systems (FHIR), and government services increasingly mandate mTLS for machine-to-machine authentication. Organizations can now:
- Meet regulatory compliance requirements without custom authentication infrastructure
- Eliminate client secret rotation challenges across distributed microservices
- Prevent token replay attacks through cryptographic binding
- Deploy zero-trust architectures with hardware-backed authentication

The implementation supports common reverse proxy scenarios (nginx, Envoy, HAProxy) where TLS termination occurs at the edge, with certificate forwarding to backend services. Automatic mTLS endpoint discovery enables clients to discover dedicated mTLS endpoints per RFC 8705 requirements.

### Device Authorization Grant (RFC 8628)

**What It Does:**

Implemented the Device Authorization Grant flow enabling OAuth 2.0 authorization for devices with limited input capabilities or no browser access, such as smart TVs, streaming devices, game consoles, and IoT devices. The implementation provides a complete flow where the device displays a user code, the user authorizes on a secondary device (phone/computer), and the device polls for token issuance.

**Features:**
- **Device Authorization Endpoint** - `/device_authorization` endpoint for initiating flows with device code and user code generation
- **Device Code Grant Handler** - Token endpoint support for `urn:ietf:params:oauth:grant-type:device_code` grant type
- **User Code Verification** - Service for validating user codes with customizable authentication UI
- **Status Tracking** - Pending, authorized, denied, and expired states per RFC 8628
- **Configurable Codes** - Support for numeric and base-20 user code formats with configurable length and expiration
- **Protocol Buffer Storage** - Efficient serialization for device authorization state
- **Rate Limiting** - Exponential backoff per user code (default: 3 failures) and per-IP sliding window (default: 10/minute)
- **Atomic Operations** - Lock-based device code redemption preventing race conditions in concurrent token requests

**Why This Matters:**

Traditional OAuth flows assume devices have browsers and keyboards. Smart TVs, streaming devices, and IoT devices struggle with these assumptions - entering URLs and passwords with a TV remote is frustrating. Device Authorization Grant solves this by delegating authentication to a phone or computer where users can type comfortably.

**Real-World Impact:**

Streaming applications, smart home devices, and enterprise IoT solutions can now implement secure OAuth 2.0 flows without requiring browsers or complex input mechanisms. Users visit a simple URL on their phone, enter the code displayed on their TV, and authorize - the TV automatically receives tokens without requiring password entry on the device.

**Security:**

The implementation includes comprehensive brute force protection as recommended by RFC 8628 Section 5.2. Exponential backoff prevents automated user code guessing attacks. Per-IP rate limiting stops distributed attacks. Atomic device code redemption prevents race conditions where concurrent requests could claim the same authorization. All rate limiting state is stored in distributed cache with Protobuf serialization for multi-instance deployments.

### SSRF Protection Enhancement

**What It Does:**

Multi-layered Server-Side Request Forgery protection through configurable options including response size limits, request timeouts, allowed URI schemes, and private network blocking enabled by default.

**New Components:**
- Secure HTTP fetcher with built-in validation
- SSRF validating HTTP message handler with security checks
- Configuration options for customizing security policies

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

New attribute-based endpoint enabling and disabling through declarative attributes applied to controllers and actions. Controllers and actions are automatically removed from routing when their corresponding endpoints are not enabled in configuration.

**Components:**
- EnabledBy attribute for declarative endpoint control
- Convention-based registration for automatic discovery
- Automatic route filtering based on endpoint configuration flags

**Why This Matters:**

Different deployment scenarios require different OAuth 2.0 endpoints. A mobile app backend might only need token introspection, while a full identity provider needs all endpoints. Previously, disabled endpoints still existed in routing tables and could potentially be accessed through misconfigurations. The new system completely removes disabled endpoints from the application, reducing attack surface and preventing accidental exposure.

**Real-World Impact:**

Security audits can now verify that unused endpoints truly don't exist rather than trusting configuration. This declarative approach makes deployment configurations self-documenting - reading the code clearly shows which endpoints are available in each configuration. Microservice architectures can deploy minimal endpoint sets, reducing memory footprint and improving startup time.

### Grant Type Discovery

**What It Does:**

Dynamic grant type discovery infrastructure through an interface allowing handlers to report their supported grant types, which the discovery endpoint automatically aggregates and publishes.

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

Extended authentication session with additional properties for email address and email verification status, preserving exact values from external authentication providers.

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

Enhanced dependency injection with keyed service support through new extension methods for decorating keyed services, enabling decorator pattern with service keys.

**Features:**
- `DecorateKeyed` extension method for keyed services
- Full parameter validation
- Support for `(IServiceProvider, object key)` factory patterns
- Comprehensive XML documentation

### UriBuilder Enhancements

Enhanced URI building with ASP.NET Core integration through new properties and methods supporting relative URIs, PathString conversion, and automatic handling of URI kind determination.

**Features:**
- Relative URI support (previously required absolute URIs)
- `PathString` property for ASP.NET Core compatibility
- Automatic handling of URI kind (absolute vs relative)
- Improved redirect URI construction

## Security Enhancements

### SSRF Validation Enhancements

The SSRF validating HTTP message handler provides multi-layered protection by blocking private IP ranges before DNS resolution, validating resolved IPs after DNS lookup, preventing DNS rebinding attacks, and enforcing HTTPS when configured.

**Protected Ranges:**
- 127.0.0.0/8 (Loopback)
- 10.0.0.0/8 (Private)
- 172.16.0.0/12 (Private)
- 192.168.0.0/16 (Private)
- ::1 (IPv6 loopback)
- fc00::/7 (IPv6 unique local)
- fe80::/10 (IPv6 link-local)

## Enhancements

### Protocol Buffer Serialization Support

**What It Does:**

Implemented Protocol Buffer (protobuf) serialization for all OIDC storage types through a new `ProtobufSerializer` implementation of `IBinarySerializer`, providing a more efficient alternative to JSON serialization for session and token storage.

**Components:**
- 8 protobuf message definitions for all storage models
- Bidirectional mapping layer with extension methods
- `ProtoMapper` utility class with shared mapping helpers
- Google well-known types for time values (Timestamp, Duration)

**Supported Storage Types:**
- `JsonWebTokenStatus` - Token revocation status
- `TokenInfo` - Access/refresh token metadata
- `RequestedClaims` - OIDC requested claims specification (with zero-serialization)
- `AuthSession` - User authentication session (with zero-serialization)
- `AuthorizationContext` - Authorization grant context
- `AuthorizedGrant` - Complete authorization grant
- `AuthorizationRequest` - Full OIDC authorization request
- `BackChannelAuthenticationRequest` - CIBA flow state

**Why This Matters:**

JSON serialization is verbose and inefficient for high-volume session storage. Protocol Buffers provide:
- **Smaller size** - Binary format significantly reduces storage footprint compared to JSON
- **Faster processing** - Binary parsing is faster than JSON text parsing
- **Type safety** - Strongly-typed schema prevents deserialization errors
- **Forward compatibility** - Optional fields enable schema evolution without breaking changes

In distributed deployments using Redis or SQL Server for session storage, reducing session size decreases memory usage, network transfer costs, and cache eviction pressure. This is especially important for high-traffic authentication services handling thousands of sessions.

**Real-World Impact:**

Production systems with thousands of active sessions see measurable benefits:
- Reduced Redis/cache memory consumption
- Lower network bandwidth between application servers and cache
- Faster session serialization/deserialization cycles
- Better cache hit rates due to smaller entry sizes

The implementation maintains full backward compatibility through the `IBinarySerializer` abstraction - applications can switch between JSON and protobuf serialization via dependency injection configuration without code changes. The default remains JSON for compatibility, with protobuf available for performance-critical deployments.

**Zero-Serialization Conversion:**

A key optimization in the protobuf implementation is the elimination of JSON string encoding for complex claim values. Traditional approaches serialize JSON objects to strings before storing in protobuf, creating double serialization overhead:

```csharp
// Traditional approach (NOT used)
proto.AdditionalClaims = Struct.Parser.ParseJson(source.AdditionalClaims.ToJsonString());
// JsonObject → JSON string → Struct (double serialization)
```

Instead, `JsonNodeExtensions` provides direct object-to-object mapping using Google's well-known types (`google.protobuf.Struct`, `google.protobuf.Value`, `google.protobuf.ListValue`):

```csharp
// Zero-serialization approach (actual implementation)
proto.AdditionalClaims = source.AdditionalClaims.ToProtoStruct();
// JsonObject → Struct (direct mapping, zero serialization)
```

**Key Features:**
- **Direct type mapping** - Pattern matching on C# types to protobuf types without intermediate JSON strings
- **Type preservation** - Whole numbers (42.0) automatically convert to `int`, fractional numbers remain `double`
- **Nested object support** - Recursive conversion handles arbitrary JSON structure depth
- **Bidirectional conversion** - Round-trip conversion preserves both values and types

**Example Conversions:**

```csharp
// RequestedClaims with claim constraints
var claims = new RequestedClaims
{
    UserInfo = new Dictionary<string, RequestedClaimDetails>
    {
        ["email"] = new() { Essential = true, Value = "user@example.com" },
        ["locale"] = new() { Values = new object[] { "en-US", "en-GB", "en" } }
    }
};

// Direct protobuf conversion (no JSON serialization)
var proto = claims.ToProto();  // Uses google.protobuf.Value and ListValue

// Round-trip preserves types
var restored = proto.FromProto();
Assert.Equal("user@example.com", restored.UserInfo["email"].Value);  // Still string
Assert.IsType<object[]>(restored.UserInfo["locale"].Values);  // Still array
```

**Type Preservation Example:**

```csharp
// Whole numbers become int, not double
var value = 42;
var proto = value.ToProtoValue();  // google.protobuf.Value
var result = proto.ToObject();
Assert.IsType<int>(result);  // Type preserved as int
Assert.Equal(42, result);

// Fractional numbers stay double
var value = 3.14;
var proto = value.ToProtoValue();
var result = proto.ToObject();
Assert.IsType<double>(result);  // Remains double
```

**Performance Impact:**
- Eliminated JSON string serialization overhead in claim storage
- Direct memory-to-memory conversion for primitives and arrays
- Reduced CPU cycles for serialization/deserialization
- Smaller protobuf messages (no escaped JSON strings)

**Test Coverage:**
- 18 serialization round-trip tests
- 20 mapper unit tests
- 38 JsonNodeExtensions conversion tests
  - Null handling
  - Primitive types (bool, int, long, float, double, decimal, string)
  - Complex nested structures (3+ levels deep)
  - Array handling (empty, homogeneous, mixed types)
  - Type preservation edge cases
  - Round-trip conversion validation
- Edge case validation (nulls, empty collections, optional fields)
- Size comparison verification

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

Fixed critical session accumulation issue with distributed cache by moving critical claims from AuthenticationProperties to ClaimsPrincipal, ensuring they're accessible in cookie authentication SignOut events for proper session cleanup.

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

Authentication scheme adapter now accepts explicit authentication scheme parameter, fixing multi-scheme authentication scenarios where multiple authentication schemes are registered.

### URI Resolution

Extracted duplicate URI resolution logic to shared extension method that handles both relative and application-relative paths, centralizing conversion to absolute URIs.

### User Info Provider Enhancement

Updated user info provider interface to accept full authentication session instead of just subject identifier, enabling access to authentication method, email from external providers, and other session context.

### Collection Expressions

**What Changed:**

Modernized entire codebase to C# 12 collection expressions, replacing empty array calls and array initializers with concise bracket syntax for improved readability and potential compiler optimizations.

**Why This Matters:**

Collection expressions are more than syntactic sugar - they enable compiler optimizations and reduce cognitive load. The concise syntax makes code intention clearer, reducing bugs from verbose initialization patterns. The compiler can optimize collection expressions more aggressively than traditional array initialization.

**Real-World Impact:**

Throughout the codebase, collection initialization patterns are now consistent and readable. Code reviews focus on logic rather than boilerplate syntax. The modernized syntax aligns with current C# best practices, making the codebase more accessible to developers familiar with modern C#.

### Client Cache Expiration

Added per-client time-to-live control for dynamic registration through optional expiration property, enabling pseudo-sliding expiration behavior in distributed cache scenarios.

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

Corrected bitwise flag values in OidcEndpoints enum to prevent conflicts, ensuring each flag uses proper power-of-two values for safe bitwise operations.

### Fixed UriBuilder Edge Cases

- Handle relative URIs without leading slash
- Omit default ports (80 for HTTP, 443 for HTTPS)
- Proper fragment handling
- PathString integration fixes

### Fixed AttributeUsage Declarations

Added explicit AttributeUsage declarations to validation attributes, specifying valid targets as properties and parameters.

### Fixed Nullability Warnings

Removed unused test projects and resolved nullability warnings across codebase.

### Fixed JSON Deserialization Edge Cases

Robust handling of claim arrays in both JSON array format and plain text format through improved deserialization logic in claims principal extensions.

### Fixed checkSession.html

Replaced deprecated `String.replace()` with `String.replaceAll()` for better browser compatibility.

## Refactoring & Code Quality

### Primary Constructors (C# 12)

Migrated entire codebase to primary constructor syntax, eliminating approximately 900 lines of constructor boilerplate across 74 classes by capturing constructor parameters directly in class declarations.

**Why This Matters:**

Primary constructors eliminate repetitive field declarations and assignment code that added no value but consumed screen space and mental energy. Removing 900 lines of boilerplate means less code to maintain, fewer merge conflicts, and clearer focus on actual business logic. The pattern also encourages immutability by making captured constructor parameters readonly by default.

**Real-World Impact:**

Code reviews become faster because reviewers can immediately see class dependencies without scrolling past constructor boilerplate. New team members can understand class structure more quickly. IDE navigation improves because there's less clutter between important methods. The reduced line count also speeds up compilation and IDE analysis.

### Type-Safe JSON Web Key Hierarchy

**What Changed:**

Established strongly-typed JSON Web Key hierarchy with abstract base record and concrete implementations for RSA, elliptic curve, and octet key types, each with algorithm-specific properties per RFC 7517.

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

Migrated JWT validation from inheritance-based result types to Result pattern with explicit success and failure generic parameters.

### Sanitized Security Pattern

Refactored log sanitization to static factory pattern, strengthening log injection prevention with clearer API semantics through named factory method.

### HttpClientHandler Encapsulation

Encapsulated HTTP client configuration in SSRF validating message handler constructor, centralizing server certificate validation callbacks, SSL protocol settings, and SSRF validation logic.

### ExcludeFromCodeCoverage Configuration

Moved ExcludeFromCodeCoverage attribute to project-level assembly attributes for consistent code coverage exclusion across test projects.

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

Fixed unit test mocking for extension methods by properly setting up mock services with explicit parameter handling for methods with optional parameters.

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

### Enable Protocol Buffer Serialization (Optional)

For performance-critical deployments, opt into protobuf serialization:

```csharp
// Replace the default JSON serializer with protobuf
services.AddSingleton<IBinarySerializer, ProtobufSerializer>();
```

**Benefits:**
- Smaller storage footprint (typically 40-60% smaller than JSON)
- Faster serialization/deserialization
- Reduced cache memory usage
- Lower network bandwidth for distributed cache scenarios

**Compatibility:**
- Fully backward compatible with existing sessions
- Can switch at any time via DI configuration
- No code changes required in application logic

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
