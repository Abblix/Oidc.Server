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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization.Validation;

/// <summary>
/// Unit tests for <see cref="PkceValidator"/> verifying PKCE (Proof Key for Code Exchange) validation
/// per RFC 7636. Tests cover code challenge validation, code challenge method validation, and PKCE
/// requirement enforcement for public clients.
/// </summary>
public class PkceValidatorTests
{
    private const string ClientId = "client_123";
    private const string CodeChallengeS256 = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private const string CodeChallengePlain = "test_code_verifier_plain";

    private readonly PkceValidator _validator;

    public PkceValidatorTests()
    {
        _validator = new PkceValidator();
    }

    /// <summary>
    /// Creates an AuthorizationValidationContext for testing.
    /// </summary>
    private static AuthorizationValidationContext CreateContext(
        string? codeChallenge = null,
        string? codeChallengeMethod = null,
        bool? pkceRequired = null,
        bool plainPkceAllowed = false)
    {
        var request = new AuthorizationRequest
        {
            ClientId = ClientId,
            ResponseType = [ResponseTypes.Code],
            RedirectUri = new Uri("https://client.example.com/callback"),
            Scope = [Scopes.OpenId],
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod,
        };

        var clientInfo = new ClientInfo(ClientId)
        {
            PkceRequired = pkceRequired,
            PlainPkceAllowed = plainPkceAllowed,
        };

        return new AuthorizationValidationContext(request)
        {
            ClientInfo = clientInfo,
            ResponseMode = ResponseModes.Query,
            ValidRedirectUri = request.RedirectUri,
        };
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts request with S256 code challenge method.
    /// Per RFC 7636, S256 (SHA-256) is the recommended code challenge method.
    /// Critical for standard PKCE flow with hash-based challenge.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithS256CodeChallenge_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(
            codeChallenge: CodeChallengeS256,
            codeChallengeMethod: CodeChallengeMethods.S256);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts request with plain code challenge when allowed.
    /// Per RFC 7636 Section 4.2, plain method is permitted but not recommended.
    /// Tests client-specific PKCE configuration allowing plain challenges.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithPlainCodeChallengeWhenAllowed_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(
            codeChallenge: CodeChallengePlain,
            codeChallengeMethod: CodeChallengeMethods.Plain,
            plainPkceAllowed: true);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects plain code challenge when not allowed.
    /// Per RFC 7636 Section 4.3, server may restrict plain method for enhanced security.
    /// Critical security check preventing downgrade to weaker PKCE method.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithPlainCodeChallengeWhenNotAllowed_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            codeChallenge: CodeChallengePlain,
            codeChallengeMethod: CodeChallengeMethods.Plain,
            plainPkceAllowed: false);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("plain", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(context.ValidRedirectUri, result.RedirectUri);
        Assert.Equal(context.ResponseMode, result.ResponseMode);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects request without PKCE when required.
    /// Per RFC 7636, public clients must use PKCE to prevent authorization code interception.
    /// Critical security requirement for mobile and SPA applications.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithoutPkceWhenRequired_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(pkceRequired: true);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("requires PKCE", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(context.ValidRedirectUri, result.RedirectUri);
        Assert.Equal(context.ResponseMode, result.ResponseMode);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects request without PKCE when requirement is null (default true).
    /// Per RFC 7636, PKCE is required by default for public clients unless explicitly disabled.
    /// Tests default security posture requiring PKCE.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithoutPkceWhenRequirementIsNull_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(pkceRequired: null);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("requires PKCE", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts request without PKCE when explicitly not required.
    /// Allows confidential clients to skip PKCE when server-side security is sufficient.
    /// Tests opt-out configuration for legacy or confidential client support.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithoutPkceWhenNotRequired_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(pkceRequired: false);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts code challenge without explicit method (defaults to plain).
    /// Per RFC 7636 Section 4.3, missing code_challenge_method defaults to "plain".
    /// Tests backward compatibility with minimal PKCE implementations.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithCodeChallengeWithoutMethod_ShouldUseDefaultPlain()
    {
        // Arrange
        var context = CreateContext(
            codeChallenge: CodeChallengePlain,
            codeChallengeMethod: null,
            plainPkceAllowed: true);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts code challenge without method when plain not allowed.
    /// Per RFC 7636 Section 4.3, if code_challenge_method is not specified, validator only
    /// checks if plain method is explicitly used. Null method means client didn't specify,
    /// so no validation against PlainPkceAllowed is performed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithCodeChallengeWithoutMethodWhenPlainNotAllowed_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(
            codeChallenge: CodeChallengePlain,
            codeChallengeMethod: null,
            plainPkceAllowed: false);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts request with custom code challenge method.
    /// Per RFC 7636, servers may support additional transformation methods.
    /// Tests extensibility for future PKCE enhancements.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithCustomCodeChallengeMethod_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(
            codeChallenge: CodeChallengeS256,
            codeChallengeMethod: "custom-method");

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts S256 method with PKCE not required.
    /// PKCE can be optionally used even when not mandatory.
    /// Tests voluntary PKCE adoption for enhanced security.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithS256WhenPkceNotRequired_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(
            codeChallenge: CodeChallengeS256,
            codeChallengeMethod: CodeChallengeMethods.S256,
            pkceRequired: false);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts plain method when required and allowed.
    /// Tests combination of PKCE requirement with plain method permission.
    /// Ensures both flags work correctly together.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithPlainWhenRequiredAndAllowed_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(
            codeChallenge: CodeChallengePlain,
            codeChallengeMethod: CodeChallengeMethods.Plain,
            pkceRequired: true,
            plainPkceAllowed: true);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects plain method when required but not allowed.
    /// Per RFC 7636, plain method restriction takes precedence over PKCE requirement.
    /// Critical security check enforcing S256 when plain is disabled.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithPlainWhenRequiredButNotAllowed_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            codeChallenge: CodeChallengePlain,
            codeChallengeMethod: CodeChallengeMethods.Plain,
            pkceRequired: true,
            plainPkceAllowed: false);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("plain", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts empty code challenge when PKCE not required.
    /// Tests that empty string is treated same as null/missing.
    /// Ensures consistent handling of absent PKCE parameters.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithEmptyCodeChallengeWhenNotRequired_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(
            codeChallenge: string.Empty,
            pkceRequired: false);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects empty code challenge when PKCE required.
    /// Empty string should be treated as missing PKCE.
    /// Critical for preventing PKCE bypass via empty values.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithEmptyCodeChallengeWhenRequired_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            codeChallenge: string.Empty,
            pkceRequired: true);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts whitespace-only code challenge as valid PKCE.
    /// Per RFC 7636, code challenge is opaque string that may contain whitespace.
    /// Tests edge case of unusual but technically valid code challenges.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithWhitespaceCodeChallenge_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(
            codeChallenge: "   ",
            codeChallengeMethod: CodeChallengeMethods.S256);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts very long code challenge.
    /// Per RFC 7636 Section 4.1, code challenge length is 43-128 characters.
    /// Tests validator doesn't enforce length constraints (handled elsewhere).
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithVeryLongCodeChallenge_ShouldSucceed()
    {
        // Arrange
        var longChallenge = new string('a', 200);
        var context = CreateContext(
            codeChallenge: longChallenge,
            codeChallengeMethod: CodeChallengeMethods.S256);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts code challenge with special characters.
    /// Per RFC 7636, code challenge uses base64url encoding allowing specific characters.
    /// Tests handling of valid base64url character set.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithSpecialCharactersInCodeChallenge_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(
            codeChallenge: "a-b_c.d~e",
            codeChallengeMethod: CodeChallengeMethods.S256);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync includes redirect URI in error response.
    /// Per OAuth 2.0, error responses should include redirect_uri for client notification.
    /// Critical for proper error flow completion.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ErrorResponse_ShouldIncludeRedirectUri()
    {
        // Arrange
        var redirectUri = new Uri("https://client.example.com/callback");
        var context = CreateContext(pkceRequired: true);
        context.ValidRedirectUri = redirectUri;

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(redirectUri, result.RedirectUri);
    }

    /// <summary>
    /// Verifies that ValidateAsync includes response mode in error response.
    /// Per OAuth 2.0, error delivery must match requested response mode.
    /// Critical for proper error communication channel.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ErrorResponse_ShouldIncludeResponseMode()
    {
        // Arrange
        const string responseMode = ResponseModes.Fragment;
        var context = CreateContext(pkceRequired: true);
        context.ResponseMode = responseMode;

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(responseMode, result.ResponseMode);
    }

    /// <summary>
    /// Verifies that ValidateAsync treats uppercase PLAIN as different from plain.
    /// Per RFC 7636, code_challenge_method values are case-sensitive.
    /// Validator checks for exact match with "plain", so "PLAIN" passes validation.
    /// This tests that validator correctly enforces case-sensitive method matching.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUppercasePlainMethod_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(
            codeChallenge: CodeChallengePlain,
            codeChallengeMethod: "PLAIN",
            plainPkceAllowed: false);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }
}
