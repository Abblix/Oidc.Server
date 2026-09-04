// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Options;
using Abblix.Oidc.Server.Features.ReusePrevention;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization.Validation;

/// <summary>
/// Unit tests for <see cref="PkceValidator"/> verifying PKCE (Proof Key for Code Exchange) validation
/// per RFC 7636. Tests cover code challenge validation, code challenge method validation, and PKCE
/// requirement enforcement for public clients.
/// </summary>
public class PkceValidatorTests
{
    private const string ClientId = TestConstants.DefaultClientId;
    private const string CodeChallengeS256 = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private const string CodeChallengePlain = "test_code_verifier_plain";

    private readonly PkceValidator _validator;

    public PkceValidatorTests()
    {
        _validator = CreateValidator();
    }

    private static PkceValidator CreateValidator(
        ClientSecurityProfile defaultSecurityProfile = ClientSecurityProfile.None,
        IAuthorizationValueReuseDetector? reuseDetector = null)
        => new(
            Options.Create(new OidcOptions { DefaultSecurityProfile = defaultSecurityProfile }),
            reuseDetector ?? Mock.Of<IAuthorizationValueReuseDetector>());

    /// <summary>
    /// Verifies that a code_challenge the client already used for a previously issued authorization code is
    /// rejected when reuse detection is enabled - a code_challenge must be transaction-specific (RFC 9700
    /// Section 2.1.1). A structurally valid S256 challenge would otherwise pass.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithReusedCodeChallenge_ShouldFail()
    {
        // Arrange
        var reuseDetector = new Mock<IAuthorizationValueReuseDetector>();
        reuseDetector
            .Setup(d => d.IsReusedAsync(ClientId, It.IsAny<string>(), CodeChallengeS256))
            .ReturnsAsync(true);
        var validator = CreateValidator(reuseDetector: reuseDetector.Object);
        var context = CreateContext(
            codeChallenge: CodeChallengeS256,
            codeChallengeMethod: CodeChallengeMethods.S256);

        // Act
        var result = await validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
    }

    /// <summary>
    /// Creates an AuthorizationValidationContext for testing.
    /// </summary>
    private static AuthorizationValidationContext CreateContext(
        string? codeChallenge = null,
        string? codeChallengeMethod = null,
        bool? pkceRequired = null,
        bool plainPkceAllowed = false,
        ClientSecurityProfile? securityProfile = null,
        string[]? responseType = null)
    {
        var request = new AuthorizationRequest
        {
            ClientId = ClientId,
            ResponseType = responseType ?? [ResponseTypes.Code],
            RedirectUri = new Uri("https://client.example.com/callback"),
            Scope = [Scopes.OpenId],
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod,
        };

        var clientInfo = new ClientInfo(ClientId)
        {
            PkceRequired = pkceRequired,
            PlainPkceAllowed = plainPkceAllowed,
            SecurityProfile = securityProfile,
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

    /// <summary>
    /// Under the FAPI 2.0 profile an S256 challenge is accepted - the profile names S256 as the sole
    /// method.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_Fapi2WithS256_ShouldSucceed()
    {
        var context = CreateContext(
            codeChallenge: CodeChallengeS256,
            codeChallengeMethod: CodeChallengeMethods.S256,
            securityProfile: ClientSecurityProfile.Fapi2);

        var result = await _validator.ValidateAsync(context);

        Assert.Null(result);
    }

    /// <summary>
    /// Under the FAPI 2.0 profile the plain method is rejected even when the client explicitly allows
    /// it: the profile tightens to S256 and the granular PlainPkceAllowed toggle cannot loosen it.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_Fapi2WithPlainEvenWhenAllowed_ShouldReturnError()
    {
        var context = CreateContext(
            codeChallenge: CodeChallengePlain,
            codeChallengeMethod: CodeChallengeMethods.Plain,
            plainPkceAllowed: true,
            securityProfile: ClientSecurityProfile.Fapi2);

        var result = await _validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("S256", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Under the FAPI 2.0 profile the non-standard S512 extension is rejected: the profile restricts
    /// the method to exactly S256 so a conformance suite never encounters S512.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_Fapi2WithS512_ShouldReturnError()
    {
        var context = CreateContext(
            codeChallenge: CodeChallengeS256,
            codeChallengeMethod: CodeChallengeMethods.S512,
            securityProfile: ClientSecurityProfile.Fapi2);

        var result = await _validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("S256", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Under the FAPI 2.0 profile a code challenge with no explicit method is rejected: a missing
    /// method defaults to plain (RFC 7636 §4.3), which is not the required S256.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_Fapi2WithChallengeAndNoMethod_ShouldReturnError()
    {
        var context = CreateContext(
            codeChallenge: CodeChallengeS256,
            codeChallengeMethod: null,
            securityProfile: ClientSecurityProfile.Fapi2);

        var result = await _validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("S256", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Under the FAPI 2.0 profile PKCE is mandatory even when the client explicitly disables it: the
    /// profile forces PKCE and the granular PkceRequired=false toggle cannot weaken it.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_Fapi2WithoutPkceEvenWhenNotRequired_ShouldReturnError()
    {
        var context = CreateContext(
            pkceRequired: false,
            securityProfile: ClientSecurityProfile.Fapi2);

        var result = await _validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("requires PKCE", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// A client that states no profile (null) inherits the server-wide DefaultSecurityProfile: a
    /// global FAPI 2.0 default restricts the method to S256 for the unprofiled client.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_GlobalDefaultFapi2_RestrictsUnprofiledClientToS256()
    {
        var validator = CreateValidator(defaultSecurityProfile: ClientSecurityProfile.Fapi2);
        var context = CreateContext(
            codeChallenge: CodeChallengePlain,
            codeChallengeMethod: CodeChallengeMethods.Plain,
            plainPkceAllowed: true,
            securityProfile: null);

        var result = await validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("S256", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// A client selecting None under a server-wide FAPI 2.0 default is still held to it: a
    /// deployment-wide profile is a floor, so naming a profile that demands nothing adds nothing and
    /// takes nothing away. The plain method the client's own toggle allows is refused all the same.
    /// </summary>
    /// <remarks>
    /// The registration that would otherwise escape here does not read as a decision to weaken the
    /// server, which is what makes the floor worth having: one such client is enough to leave a
    /// deployment serving requests under none of the controls it turned on.
    /// </remarks>
    [Fact]
    public async Task ValidateAsync_ExplicitNoneUnderGlobalDefaultFapi2_StillRefusesPlain()
    {
        var validator = CreateValidator(defaultSecurityProfile: ClientSecurityProfile.Fapi2);
        var context = CreateContext(
            codeChallenge: CodeChallengePlain,
            codeChallengeMethod: CodeChallengeMethods.Plain,
            plainPkceAllowed: true,
            securityProfile: ClientSecurityProfile.None);

        var result = await validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("S256", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// A pure implicit request (response_type=token, no authorization code) must not be rejected for a
    /// missing PKCE code challenge even for a default client (PkceRequired defaults to true): RFC 7636
    /// PKCE protects the code exchange, and a pure implicit flow issues no code to protect.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_PureImplicitToken_WithoutCodeChallenge_ShouldSucceed()
    {
        var context = CreateContext(
            responseType: [ResponseTypes.Token],
            pkceRequired: null);

        var result = await _validator.ValidateAsync(context);

        Assert.Null(result);
    }

    /// <summary>
    /// A pure implicit request (response_type=id_token, no code) must not be rejected for a missing PKCE
    /// code challenge even when the client explicitly sets PkceRequired=true: there is no authorization
    /// code exchange in a pure implicit flow for PKCE (RFC 7636) to apply to.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_PureImplicitIdToken_WhenPkceRequired_ShouldSucceed()
    {
        var context = CreateContext(
            responseType: [ResponseTypes.IdToken],
            pkceRequired: true);

        var result = await _validator.ValidateAsync(context);

        Assert.Null(result);
    }

    /// <summary>
    /// A hybrid request (response_type=code id_token) still returns an authorization code, so PKCE
    /// enforcement remains in force: a missing code challenge with PKCE required is still rejected. This
    /// guards the fix from over-loosening to any token-bearing response type.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_HybridWithoutCodeChallenge_WhenRequired_ShouldReturnError()
    {
        var context = CreateContext(
            responseType: [ResponseTypes.Code, ResponseTypes.IdToken],
            pkceRequired: true);

        var result = await _validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("requires PKCE", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }
}
