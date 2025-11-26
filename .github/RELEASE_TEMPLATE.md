<!--
Release Template for Abblix OIDC Server
Based on actual release format from v1.2.0, v1.5, v1.6

Usage:
1. Copy this template when creating a new release
2. Update [VERSION] placeholders
3. Fill in relevant sections (remove unused sections)
4. Expand each feature/fix in "Detailed description" section
-->

🚨 Breaking Changes
-------------------

<!-- Include this section only for major releases with breaking changes -->
<!-- Example from v2.0.0:
- **Result Pattern Migration**: Completely migrated to `Result<TSuccess, TFailure>` pattern
  - All handler methods now return `Result<TSuccess, TFailure>` instead of throwing exceptions
  - See [MIGRATION-2.0.md](MIGRATION-2.0.md) for detailed migration guide
- **Framework Support Changes**: Dropped .NET 6 and .NET 7 support
  - Now exclusively targets .NET 8 (LTS), .NET 9, and .NET 10
- **API Simplification**: All response types renamed to remove redundant 'Response' suffix
  - `SuccessfulAuthorizationResponse` → `SuccessfulAuthorization`
  - `AuthorizationErrorResponse` → `AuthorizationError`
-->

🚀 Features
-----------

<!-- List new features with PR links -->
<!-- Examples:
- Added support for [Client-Initiated Backchannel Authentication](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html) (CIBA) ([PR#17](https://github.com/Abblix/Oidc.Server/pull/17))
- Multi-value claim support ([PR#23](https://github.com/Abblix/Oidc.Server/pull/23))
- Implemented `client_secret_jwt` authentication method ([PR#35](https://github.com/Abblix/Oidc.Server/pull/35))
-->

✏️ Improvements
---------------

<!-- List enhancements and performance improvements -->
<!-- Examples:
- Faster Base32 encode/decode operations
- Fixed all XX nullability warnings for improved type safety
- Migrated to primary constructor syntax for cleaner code
- Updated Microsoft.Extensions.* packages to 9.0.10
- Updated System.IdentityModel.Tokens.Jwt to 8.14.0
-->

🛠 Fixes
--------

<!-- List bug fixes with PR/issue links if available -->
<!-- Examples:
- Fixed routing-template resolution ([PR#24](https://github.com/Abblix/Oidc.Server/pull/24))
- Handle relative URIs without leading slash in UriBuilder
- Omit default ports (80 for HTTP, 443 for HTTPS) in UriBuilder output
- Resolved SignOut cookie issues with explicit authentication scheme ([PR#31](https://github.com/Abblix/Oidc.Server/pull/31))
-->

🔒 Security
-----------

<!-- Include security-related changes -->
<!-- Examples:
- Enhanced SSRF protection with multi-layered security approach
  - Added DNS resolution validation before HTTP requests
  - Implemented IP-based blocking for private network ranges
  - Note: TOCTOU vulnerability exists between DNS validation and HTTP request
- Hardened GitHub Actions workflow against supply chain attacks
  - Pinned all GitHub Actions to commit SHA instead of mutable version tags
- Fixed Denial of Service vulnerability in cryptography libraries
-->

Detailed description
--------------------

<!-- Provide detailed explanations for each major feature/fix listed above -->
<!-- Use bold headers for each item, then explain in detail with bullet points -->
<!-- Examples:

**Added support for CIBA with a dedicated endpoint compliant with the Client-Initiated Backchannel Authentication (CIBA) standard**

- Added support for CIBA with a dedicated endpoint compliant with the Client-Initiated Backchannel Authentication (CIBA) standard. This allows clients to initiate authentication through a secure backchannel.
- Supports Signed Authentication Requests, allowing clients to send JWS-signed requests for enhanced security. This ensures that the requests are tamper-proof and that their integrity can be verified by the server.
- The token endpoint now supports Poll Mode for CIBA, enabling clients to poll for tokens during the backchannel authentication process.
- Full support for the CIBA grant type (`urn:openid:params:grant-type:ciba`) at the token endpoint, ensuring seamless token exchange once authentication is completed.

**Multi-value claim support**

- JWTs that previously dropped all but the first value for repeated claim types (e.g., multiple roles) now correctly emit arrays. The Abblix.JWT package now aggregates claims of the same type into JSON arrays and parses them back accurately.

**Fixed routing-template resolution**

- The original token parser used a regex that stopped capturing fallback values at the first closing bracket, and its resolution loop could exit before all placeholders were replaced—resulting in literal `[route:…]` fragments, malformed templates, and startup-time 404s. We broadened the regex to capture any character in the fallback and improved the loop to run until no further substitutions occur.
-->

---

**Full Changelog**: https://github.com/Abblix/Oidc.Server/compare/v[PREVIOUS_VERSION]...v[VERSION]
