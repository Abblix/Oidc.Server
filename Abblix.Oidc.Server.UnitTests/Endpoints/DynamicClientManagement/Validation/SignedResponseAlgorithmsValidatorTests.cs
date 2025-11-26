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
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
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
    private readonly Mock<IJsonWebTokenCreator> _jwtCreator;
    private readonly SignedResponseAlgorithmsValidator _validator;

    public SignedResponseAlgorithmsValidatorTests()
    {
        _jwtCreator = new Mock<IJsonWebTokenCreator>(MockBehavior.Strict);
        _validator = new SignedResponseAlgorithmsValidator(_jwtCreator.Object);
    }

    private ClientRegistrationValidationContext CreateContext(
        string? idTokenSignedResponseAlg = null,
        string? userInfoSignedResponseAlg = null)
    {
        var request = new ClientRegistrationRequest
        {
            RedirectUris = [new Uri(TestConstants.DefaultRedirectUri)],
            IdTokenSignedResponseAlg = idTokenSignedResponseAlg,
            UserInfoSignedResponseAlg = userInfoSignedResponseAlg
        };

        return new ClientRegistrationValidationContext(request);
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
        _jwtCreator
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
        _jwtCreator
            .Setup(c => c.SignedResponseAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256]);

        var context = CreateContext(idTokenSignedResponseAlg: SigningAlgorithms.ES512);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("id_token_signed_response_alg", result.ErrorDescription);
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
        _jwtCreator
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
        _jwtCreator
            .Setup(c => c.SignedResponseAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256]);

        var context = CreateContext(userInfoSignedResponseAlg: SigningAlgorithms.PS384);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("userinfo_signed_response_alg", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies validation succeeds with both supported algorithms.
    /// Multiple response signing algorithms can be specified simultaneously.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithBothSupportedAlgorithms_ShouldReturnNull()
    {
        // Arrange
        _jwtCreator
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
        _jwtCreator
            .Setup(c => c.SignedResponseAlgorithmsSupported)
            .Returns([SigningAlgorithms.ES256]);

        var context = CreateContext(
            idTokenSignedResponseAlg: SigningAlgorithms.RS256, // Unsupported - should fail here
            userInfoSignedResponseAlg: SigningAlgorithms.ES256);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Contains("id_token_signed_response_alg", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies algorithm comparison is case-sensitive.
    /// Per OAuth 2.0 and JOSE, algorithm names are case-sensitive.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithDifferentCase_ShouldReturnError()
    {
        // Arrange
        _jwtCreator
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
        _jwtCreator
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
        _jwtCreator
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
        _jwtCreator
            .Setup(c => c.SignedResponseAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256]);

        var context = CreateContext(idTokenSignedResponseAlg: SigningAlgorithms.RS256);

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        _jwtCreator.Verify(c => c.SignedResponseAlgorithmsSupported, Times.Once);
    }

    /// <summary>
    /// Verifies validation succeeds with none algorithm for UserInfo.
    /// Per OIDC Core, unsigned UserInfo responses may be supported.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoneAlgorithmForUserInfo_ShouldValidate()
    {
        // Arrange
        _jwtCreator
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
        _jwtCreator
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
        _jwtCreator
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
