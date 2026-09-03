// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Unit tests for <see cref="SignedResponseAlgorithmsValidator"/> verifying
/// signed response algorithm validation per OpenID Connect specifications.
/// </summary>
public class SignedResponseAlgorithmsValidatorTests
{
    private readonly Mock<IJwtAlgorithmsProvider> _jwtAlgorithms;
    private readonly SignedResponseAlgorithmsValidator _validator;

    public SignedResponseAlgorithmsValidatorTests()
    {
        _jwtAlgorithms = new Mock<IJwtAlgorithmsProvider>(MockBehavior.Strict);
        _validator = new SignedResponseAlgorithmsValidator(_jwtAlgorithms.Object);
    }

    private ClientRegistrationValidationContext CreateContext(
        string? idTokenSignedResponseAlg = null,
        string? userInfoSignedResponseAlg = null,
        string? authorizationSignedResponseAlg = null,
        string? introspectionSignedResponseAlg = null)
    {
        var request = new ClientRegistrationRequest
        {
            RedirectUris = [TestConstants.DefaultRedirectUri],
            IdTokenSignedResponseAlg = idTokenSignedResponseAlg,
            UserInfoSignedResponseAlg = userInfoSignedResponseAlg,
            AuthorizationSignedResponseAlg = authorizationSignedResponseAlg,
            IntrospectionSignedResponseAlg = introspectionSignedResponseAlg
        };

        return new ClientRegistrationValidationContext(request);
    }

    /// <summary>
    /// OIDC Registration 1.0 section 2: id_token_signed_response_alg=none is allowed only for response
    /// types that return no ID Token from the authorization endpoint - an unsigned ID Token
    /// delivered through the browser would be modifiable in transit.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_NoneIdTokenAlg_WithIdTokenResponseType_ShouldReturnError()
    {
        _jwtAlgorithms
            .Setup(c => c.SignedResponseAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256, SigningAlgorithms.None]);

        var context = new ClientRegistrationValidationContext(new ClientRegistrationRequest
        {
            RedirectUris = [TestConstants.DefaultRedirectUri],
            IdTokenSignedResponseAlg = SigningAlgorithms.None,
            ResponseTypes = [[ResponseTypes.Code, ResponseTypes.IdToken]],
        });

        var result = await _validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
    }

    /// <summary>
    /// The same none algorithm stays acceptable for the pure Authorization Code Flow, where the
    /// ID Token is delivered from the token endpoint over TLS instead of through the browser.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_NoneIdTokenAlg_WithCodeOnlyResponseType_ShouldReturnNull()
    {
        _jwtAlgorithms
            .Setup(c => c.SignedResponseAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256, SigningAlgorithms.None]);

        var context = new ClientRegistrationValidationContext(new ClientRegistrationRequest
        {
            RedirectUris = [TestConstants.DefaultRedirectUri],
            IdTokenSignedResponseAlg = SigningAlgorithms.None,
            ResponseTypes = [[ResponseTypes.Code]],
        });

        var result = await _validator.ValidateAsync(context);

        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with a supported introspection_signed_response_alg (RFC 9701).
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithSupportedIntrospectionAlg_ShouldReturnNull()
    {
        _jwtAlgorithms
            .Setup(c => c.SignedResponseAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256, SigningAlgorithms.ES256]);

        var context = CreateContext(introspectionSignedResponseAlg: SigningAlgorithms.ES256);

        var result = await _validator.ValidateAsync(context);

        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error when introspection_signed_response_alg is not supported (RFC 9701).
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUnsupportedIntrospectionAlg_ShouldReturnError()
    {
        _jwtAlgorithms
            .Setup(c => c.SignedResponseAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256]);

        var context = CreateContext(introspectionSignedResponseAlg: SigningAlgorithms.PS384);

        var result = await _validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains(ClientRegistrationRequest.Parameters.IntrospectionSignedResponseAlg, result.ErrorDescription);
    }

    /// <summary>
    /// Verifies validation succeeds with a supported JARM authorization_signed_response_alg (JARM section 3).
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithSupportedAuthorizationAlg_ShouldReturnNull()
    {
        _jwtAlgorithms
            .Setup(c => c.SignedResponseAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256, SigningAlgorithms.ES256]);

        var context = CreateContext(authorizationSignedResponseAlg: SigningAlgorithms.ES256);

        var result = await _validator.ValidateAsync(context);

        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error when the JARM authorization_signed_response_alg is not supported.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUnsupportedAuthorizationAlg_ShouldReturnError()
    {
        _jwtAlgorithms
            .Setup(c => c.SignedResponseAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256]);

        var context = CreateContext(authorizationSignedResponseAlg: SigningAlgorithms.ES512);

        var result = await _validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains(ClientRegistrationRequest.Parameters.AuthorizationSignedResponseAlg, result.ErrorDescription);
    }

    /// <summary>
    /// Verifies the JARM authorization response cannot be signed with <c>none</c> (JARM section 3 forbids it),
    /// even when the server otherwise advertises <c>none</c> (e.g. for unsigned UserInfo).
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoneForAuthorizationAlg_ShouldReturnError()
    {
        _jwtAlgorithms
            .Setup(c => c.SignedResponseAlgorithmsSupported)
            .Returns([SigningAlgorithms.None, SigningAlgorithms.RS256]);

        var context = CreateContext(authorizationSignedResponseAlg: SigningAlgorithms.None);

        var result = await _validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains(ClientRegistrationRequest.Parameters.AuthorizationSignedResponseAlg, result.ErrorDescription);
    }

    /// <summary>
    /// Verifies validation succeeds when no signed response algorithms specified.
    /// Per OIDC DCR, response signing algorithm parameters are optional.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoAlgorithms_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext();

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with supported ID token signed response algorithm.
    /// Per OIDC Core, id_token_signed_response_alg must be from supported algorithms.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithSupportedIdTokenAlg_ShouldReturnNull()
    {
        // Arrange
        _jwtAlgorithms
            .Setup(c => c.SignedResponseAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256, SigningAlgorithms.ES256]);

        var context = CreateContext(idTokenSignedResponseAlg: SigningAlgorithms.RS256);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error when ID token signed response algorithm not supported.
    /// Per OIDC Core, only advertised algorithms are allowed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUnsupportedIdTokenAlg_ShouldReturnError()
    {
        // Arrange
        _jwtAlgorithms
            .Setup(c => c.SignedResponseAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256]);

        var context = CreateContext(idTokenSignedResponseAlg: SigningAlgorithms.ES512);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains(ClientRegistrationRequest.Parameters.IdTokenSignedResponseAlg, result.ErrorDescription);
        Assert.Contains("not supported", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies validation succeeds with supported UserInfo signed response algorithm.
    /// Per OIDC Core, userinfo_signed_response_alg must be from supported algorithms.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithSupportedUserInfoAlg_ShouldReturnNull()
    {
        // Arrange
        _jwtAlgorithms
            .Setup(c => c.SignedResponseAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256, SigningAlgorithms.ES256]);

        var context = CreateContext(userInfoSignedResponseAlg: SigningAlgorithms.ES256);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error when UserInfo signed response algorithm not supported.
    /// Per OIDC Core, only provider-supported algorithms allowed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUnsupportedUserInfoAlg_ShouldReturnError()
    {
        // Arrange
        _jwtAlgorithms
            .Setup(c => c.SignedResponseAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256]);

        var context = CreateContext(userInfoSignedResponseAlg: SigningAlgorithms.PS384);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains(ClientRegistrationRequest.Parameters.UserInfoSignedResponseAlg, result.ErrorDescription);
    }

    /// <summary>
    /// Verifies validation succeeds with both supported algorithms.
    /// Multiple response signing algorithms can be specified simultaneously.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithBothSupportedAlgorithms_ShouldReturnNull()
    {
        // Arrange
        _jwtAlgorithms
            .Setup(c => c.SignedResponseAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256, SigningAlgorithms.ES256]);

        var context = CreateContext(
            idTokenSignedResponseAlg: SigningAlgorithms.RS256,
            userInfoSignedResponseAlg: SigningAlgorithms.ES256);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error stops at first unsupported algorithm.
    /// Validation should fail fast on first error (ID token checked first).
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithIdTokenAlgUnsupported_ShouldReturnErrorForIdToken()
    {
        // Arrange
        _jwtAlgorithms
            .Setup(c => c.SignedResponseAlgorithmsSupported)
            .Returns([SigningAlgorithms.ES256]);

        var context = CreateContext(
            idTokenSignedResponseAlg: SigningAlgorithms.RS256, // Unsupported - should fail here
            userInfoSignedResponseAlg: SigningAlgorithms.ES256);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Contains(ClientRegistrationRequest.Parameters.IdTokenSignedResponseAlg, result.ErrorDescription);
    }

    /// <summary>
    /// Verifies algorithm comparison is case-sensitive.
    /// Per OAuth 2.0 and JOSE, algorithm names are case-sensitive.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithDifferentCase_ShouldReturnError()
    {
        // Arrange
        _jwtAlgorithms
            .Setup(c => c.SignedResponseAlgorithmsSupported)
            .Returns(["RS256"]);

        var context = CreateContext(idTokenSignedResponseAlg: "rs256"); // Different case

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies validation with multiple supported algorithms.
    /// Provider may support multiple signing algorithms for responses.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMultipleSupportedAlgs_ShouldValidateCorrectly()
    {
        // Arrange
        _jwtAlgorithms
            .Setup(c => c.SignedResponseAlgorithmsSupported)
            .Returns([
                SigningAlgorithms.RS256,
                SigningAlgorithms.RS384,
                SigningAlgorithms.RS512,
                SigningAlgorithms.ES256,
                SigningAlgorithms.ES384,
                SigningAlgorithms.ES512,
                SigningAlgorithms.PS256,
                SigningAlgorithms.PS384,
                SigningAlgorithms.PS512
            ]);

        var context = CreateContext(
            idTokenSignedResponseAlg: SigningAlgorithms.PS512,
            userInfoSignedResponseAlg: SigningAlgorithms.ES384);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation with custom/unknown algorithm.
    /// Only JOSE standard or provider-specific advertised algorithms allowed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithCustomAlgorithm_ShouldReturnError()
    {
        // Arrange
        _jwtAlgorithms
            .Setup(c => c.SignedResponseAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256]);

        var context = CreateContext(idTokenSignedResponseAlg: "custom-signing-alg");

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies validator checks provider's supported response algorithms.
    /// Ensures proper delegation to JWT creator.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldCheckJwtCreatorAlgorithms()
    {
        // Arrange
        _jwtAlgorithms
            .Setup(c => c.SignedResponseAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256]);

        var context = CreateContext(idTokenSignedResponseAlg: SigningAlgorithms.RS256);

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        _jwtAlgorithms.Verify(c => c.SignedResponseAlgorithmsSupported, Times.Once);
    }

    /// <summary>
    /// Verifies validation succeeds with none algorithm for UserInfo.
    /// Per OIDC Core, unsigned UserInfo responses may be supported.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoneAlgorithmForUserInfo_ShouldValidate()
    {
        // Arrange
        _jwtAlgorithms
            .Setup(c => c.SignedResponseAlgorithmsSupported)
            .Returns([SigningAlgorithms.None, SigningAlgorithms.RS256]);

        var context = CreateContext(userInfoSignedResponseAlg: SigningAlgorithms.None);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error when none algorithm not explicitly supported.
    /// Provider must explicitly advertise \"none\" if accepting unsigned responses.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoneAlgNotSupported_ShouldReturnError()
    {
        // Arrange
        _jwtAlgorithms
            .Setup(c => c.SignedResponseAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256]);

        var context = CreateContext(idTokenSignedResponseAlg: SigningAlgorithms.None);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies validation with same algorithm for both parameters.
    /// Client may use same algorithm for ID token and UserInfo responses.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithSameAlgForBoth_ShouldReturnNull()
    {
        // Arrange
        _jwtAlgorithms
            .Setup(c => c.SignedResponseAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256]);

        var context = CreateContext(
            idTokenSignedResponseAlg: SigningAlgorithms.RS256,
            userInfoSignedResponseAlg: SigningAlgorithms.RS256);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }
}
