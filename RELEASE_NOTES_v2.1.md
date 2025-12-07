# Version 2.1

## 🚀 Features
- ECDSA Support for JWT Signing and Encryption - ES256/ES384/ES512 signing algorithms (RFC 7518) with NIST curves P-256, P-384, P-521
- RFC 7592 Dynamic Client Registration Management - PUT operation for updating client configurations with credentials validation
- RFC 9101 JWT Secured Authorization Request - Lifetime validation prevents replay attacks using expired request objects

## 🛠 Fixes
- Client Authentication Method Validation - Validates authentication method compatibility before attempting authentication with clearer error messages
- Request Object Lifetime Validation - Server properly rejects expired request objects to prevent replay attacks
- Client Jwt Validator Cache Pollution Prevention - Eliminated shared mutable state across concurrent JWT validations
- Malformed JWT Token Handling - Gracefully handles JWT tokens with out-of-range timestamps to prevent application crashes

## Detailed Description

**ECDSA Support for JWT Signing and Encryption**
- Added support for Elliptic Curve Digital Signature Algorithm (ECDSA) with ES256/ES384/ES512 signing algorithms per RFC 7518. ECDSA offers equivalent security with significantly smaller key sizes (256-bit ECDSA ≈ 3072-bit RSA), resulting in faster cryptographic operations, reduced CPU usage, and smaller token sizes. Critical for mobile applications, IoT devices, and high-throughput scenarios where computational efficiency matters. Enables compliance with modern security standards that mandate or prefer elliptic curve cryptography.

**RFC 7592 Dynamic Client Registration Management**
- Complete implementation of OAuth 2.0 Dynamic Client Registration Management Protocol providing PUT operation for updating client configurations with RFC 7592 compliant URI format for client management endpoints. Includes credentials validation for registration requests and exposes TokenEndpointAuthMethod in client registration responses for proper client authentication method discovery.

**RFC 9101 JWT Secured Authorization Request (JAR)**
- Improved security and compliance for JWT-secured authorization requests through lifetime validation. Server now prevents replay attacks by properly rejecting expired request objects based on exp/nbf claims. Critical for financial-grade APIs and high-security deployments where request integrity over time is essential.

**Client Jwt Validator Cache Pollution Prevention**
- Fixed critical thread-safety issue where shared mutable state across concurrent JWT validations could cause validation interference. Eliminated potential security vulnerabilities from race conditions in JWT validator. Ensures thread-safe concurrent validations for high-throughput production environments.

**Client Authentication Method Validation**
- Fixed authentication flow to check that the client's configured authentication method matches the request before attempting authentication. Now distinguishes "method not attempted" (wrong method type) from "authentication failed" (correct method, wrong credentials) for easier troubleshooting.

## ✅ Why It Matters
- ECDSA support enables modern cryptography with smaller keys, faster operations
- RFC 7592 enables dynamic client lifecycle management for SaaS platforms and multi-tenant deployments
- JAR lifetime validation strengthens security posture against replay attacks for financial-grade APIs
- Thread-safe JWT validation prevents race conditions in high-concurrency production environments

## What's Changed
Full Changelog: [v2.0.1...v2.1](https://github.com/Abblix/Oidc.Server/compare/v2.0.1...v2.1)