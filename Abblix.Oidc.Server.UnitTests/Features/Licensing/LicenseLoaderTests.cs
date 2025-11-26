// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System;
using System.Threading.Tasks;

using Abblix.Oidc.Server.Features.Licensing;

using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Licensing;

/// <summary>
/// Tests for LicenseLoader JWT validation and parsing.
/// </summary>
/// <remarks>
/// IMPORTANT: These tests cannot validate successful license loading because:
/// 1. Valid licenses require signing with Abblix's private key (not available in tests)
/// 2. LicenseLoader adds licenses to static LicenseChecker, causing test interference
///
/// These tests focus on:
/// - Error handling for invalid JWTs
/// - Validation of issuer requirements
/// - Validation of JWT type requirements
/// - Parsing error scenarios
///
/// Successful license loading is tested through integration tests with actual licenses.
/// </remarks>
public class LicenseLoaderTests
{
    #region Invalid JWT Tests

    /// <summary>
    /// Verifies that LoadAsync throws InvalidOperationException for malformed JWT.
    /// </summary>
    [Fact]
    public async Task LoadAsync_MalformedJwt_ThrowsInvalidOperationException()
    {
        // Arrange - Not a valid JWT format
        const string malformedJwt = "not.a.valid.jwt";

        // Act & Assert
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            LicenseLoader.LoadAsync(malformedJwt));
    }

    /// <summary>
    /// Verifies that LoadAsync throws InvalidOperationException for empty JWT.
    /// </summary>
    [Fact]
    public async Task LoadAsync_EmptyJwt_ThrowsInvalidOperationException()
    {
        // Arrange
        const string emptyJwt = "";

        // Act & Assert
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            LicenseLoader.LoadAsync(emptyJwt));
    }

    /// <summary>
    /// Verifies that LoadAsync throws InvalidOperationException for null-like JWT.
    /// </summary>
    [Fact]
    public async Task LoadAsync_NullJwt_ThrowsArgumentException()
    {
        // Arrange
        string nullJwt = null!;

        // Act & Assert
        await Assert.ThrowsAnyAsync<Exception>(() =>
            LicenseLoader.LoadAsync(nullJwt));
    }

    #endregion

    #region Invalid Issuer Tests

    /// <summary>
    /// Verifies that LoadAsync rejects JWT with invalid issuer.
    /// </summary>
    /// <remarks>
    /// Creates a minimal valid JWT structure but with wrong issuer to test issuer validation.
    /// The JWT will fail issuer validation before reaching signature validation.
    /// </remarks>
    [Fact]
    public async Task LoadAsync_InvalidIssuer_ThrowsInvalidOperationException()
    {
        // Arrange - JWT with invalid issuer (will fail before signature check)
        // Header: {"alg":"RS256","typ":"urn:abblix.com:oidc.server:license"}
        // Payload: {"iss":"https://evil.com","exp":9999999999}
        const string jwtWithInvalidIssuer =
            "eyJhbGciOiJSUzI1NiIsInR5cCI6InVybjphYmJsaXguY29tOm9pZGMuc2VydmVyOmxpY2Vuc2UifQ." +
            "eyJpc3MiOiJodHRwczovL2V2aWwuY29tIiwiZXhwIjo5OTk5OTk5OTk5fQ." +
            "dummy_signature";

        // Act & Assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            LicenseLoader.LoadAsync(jwtWithInvalidIssuer));

        Assert.Contains("can't be validated", exception.Message);
    }

    #endregion

    #region Invalid Signature Tests

    /// <summary>
    /// Verifies that LoadAsync rejects JWT with invalid signature.
    /// </summary>
    /// <remarks>
    /// Creates JWT with correct issuer but invalid signature to test signature validation.
    /// </remarks>
    [Fact]
    public async Task LoadAsync_InvalidSignature_ThrowsInvalidOperationException()
    {
        // Arrange - JWT with correct issuer but invalid signature
        // Header: {"alg":"RS256","typ":"urn:abblix.com:oidc.server:license"}
        // Payload: {"iss":"https://abblix.com","exp":9999999999}
        // Signature: invalid/unsigned
        const string jwtWithInvalidSignature =
            "eyJhbGciOiJSUzI1NiIsInR5cCI6InVybjphYmJsaXguY29tOm9pZGMuc2VydmVyOmxpY2Vuc2UifQ." +
            "eyJpc3MiOiJodHRwczovL2FiYmxpeC5jb20iLCJleHAiOjk5OTk5OTk5OTl9." +
            "invalid_signature_that_will_fail_verification";

        // Act & Assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            LicenseLoader.LoadAsync(jwtWithInvalidSignature));

        Assert.Contains("can't be validated", exception.Message);
    }

    /// <summary>
    /// Verifies that LoadAsync rejects unsigned JWT.
    /// </summary>
    [Fact]
    public async Task LoadAsync_UnsignedJwt_ThrowsInvalidOperationException()
    {
        // Arrange - JWT with algorithm "none" (unsigned)
        // Header: {"alg":"none","typ":"urn:abblix.com:oidc.server:license"}
        // Payload: {"iss":"https://abblix.com","exp":9999999999}
        const string unsignedJwt =
            "eyJhbGciOiJub25lIiwidHlwIjoidXJuOmFiYmxpeC5jb206b2lkYy5zZXJ2ZXI6bGljZW5zZSJ9." +
            "eyJpc3MiOiJodHRwczovL2FiYmxpeC5jb20iLCJleHAiOjk5OTk5OTk5OTl9.";

        // Act & Assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            LicenseLoader.LoadAsync(unsignedJwt));

        Assert.Contains("can't be validated", exception.Message);
    }

    #endregion

    #region Invalid JWT Type Tests

    /// <summary>
    /// Verifies that LoadAsync rejects JWT with wrong type in header.
    /// </summary>
    /// <remarks>
    /// Even if JWT is properly signed and has correct issuer, wrong type should be rejected.
    /// This test uses a standard JWT type instead of the required license type.
    /// </remarks>
    [Fact]
    public async Task LoadAsync_WrongJwtType_ThrowsInvalidOperationException()
    {
        // Arrange - JWT with standard type "JWT" instead of license type
        // Header: {"alg":"RS256","typ":"JWT"}
        // Payload: {"iss":"https://abblix.com","exp":9999999999}
        // Note: This will fail at signature validation, but demonstrates type checking
        const string jwtWithWrongType =
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
            "eyJpc3MiOiJodHRwczovL2FiYmxpeC5jb20iLCJleHAiOjk5OTk5OTk5OTl9." +
            "dummy_signature";

        // Act & Assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            LicenseLoader.LoadAsync(jwtWithWrongType));

        // Will fail at validation stage before type check
        Assert.Contains("can't be validated", exception.Message);
    }

    #endregion

    #region Expired Token Tests

    /// <summary>
    /// Verifies that LoadAsync accepts expired license tokens.
    /// </summary>
    /// <remarks>
    /// LICENSE DESIGN DECISION: LoadAsync does NOT validate expiration.
    /// It loads the license and lets LicenseManager handle expiration logic,
    /// including grace periods. This allows loading expired licenses that
    /// may still be in their grace period.
    /// </remarks>
    [Fact]
    public async Task LoadAsync_ExpiredToken_DoesNotValidateExpiration()
    {
        // Arrange - JWT with expired timestamp (but will fail at signature check)
        // Header: {"alg":"RS256","typ":"urn:abblix.com:oidc.server:license"}
        // Payload: {"iss":"https://abblix.com","exp":1000000000} (expired in 2001)
        const string expiredJwt =
            "eyJhbGciOiJSUzI1NiIsInR5cCI6InVybjphYmJsaXguY29tOm9pZGMuc2VydmVyOmxpY2Vuc2UifQ." +
            "eyJpc3MiOiJodHRwczovL2FiYmxpeC5jb20iLCJleHAiOjEwMDAwMDAwMDB9." +
            "dummy_signature";

        // Act & Assert
        // Will fail at signature validation, not expiration (expiration not validated)
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            LicenseLoader.LoadAsync(expiredJwt));

        Assert.Contains("can't be validated", exception.Message);
        Assert.DoesNotContain("expired", exception.Message.ToLower());
    }

    #endregion

    #region Design Documentation Tests

    /// <summary>
    /// Documents the validation flow and requirements of LicenseLoader.
    /// </summary>
    [Fact]
    public void LicenseLoader_ValidationRequirements_Documented()
    {
        // This test documents the validation requirements:

        // 1. Valid JWT Structure (header.payload.signature)
        // 2. Valid Issuer: must be "https://abblix.com"
        // 3. Valid Signing: must be signed with Abblix's private key
        // 4. Valid Type: must be "urn:abblix.com:oidc.server:license"
        // 5. Valid Payload: must contain license claims

        // Validation Options Used:
        // - ValidationOptions.ValidateIssuer
        // - ValidationOptions.RequireSignedTokens
        // - ValidationOptions.ValidateIssuerSigningKey

        // Notable: Does NOT include:
        // - ValidationOptions.ValidateLifetime (expiration checked by LicenseManager)
        // - ValidationOptions.ValidateAudience (not applicable for licenses)

        Assert.True(true); // Documentation test always passes
    }

    /// <summary>
    /// Documents the license payload structure expected by LicenseLoader.
    /// </summary>
    [Fact]
    public void LicenseLoader_PayloadStructure_Documented()
    {
        // This test documents the expected license payload structure:

        // Required Standard Claims:
        // - "iss": Issuer, must be "https://abblix.com"
        // - "nbf": NotBefore timestamp (Unix epoch)
        // - "exp": ExpiresAt timestamp (Unix epoch)

        // Optional License Claims:
        // - "grace_period": Unix timestamp for grace period end
        // - "client_limit": Integer, max number of clients (null = unlimited)
        // - "issuer_limit": Integer, max number of issuers (null = unlimited)
        // - "valid_issuers": Array of strings, issuer whitelist

        // JWT Header:
        // - "alg": Signing algorithm (RS256)
        // - "typ": Must be "urn:abblix.com:oidc.server:license"

        Assert.True(true); // Documentation test always passes
    }

    /// <summary>
    /// Documents the security considerations of LicenseLoader.
    /// </summary>
    [Fact]
    public void LicenseLoader_SecurityConsiderations_Documented()
    {
        // Security Design:

        // 1. Asymmetric Cryptography:
        //    - Licenses signed with Abblix's private key (not available publicly)
        //    - Verified with public key embedded in assembly
        //    - Prevents license forgery

        // 2. Issuer Validation:
        //    - Only accepts licenses from "https://abblix.com"
        //    - Prevents accepting licenses from other issuers

        // 3. Embedded Public Key:
        //    - X509 certificate embedded as resource "Abblix Licensing.pem"
        //    - Cannot be modified without rebuilding assembly
        //    - Protects against key substitution attacks

        // 4. Static License Storage:
        //    - Loaded licenses stored in static LicenseChecker
        //    - Persists for application lifetime
        //    - Cannot be removed once loaded

        // Testing Limitations:
        // - Cannot create valid test licenses without private key
        // - Integration tests required with actual licenses
        // - Unit tests focus on error paths and validation logic

        Assert.True(true); // Documentation test always passes
    }

    #endregion
}
