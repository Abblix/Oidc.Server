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

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Unit tests for <see cref="SigningAlgorithmsValidator"/> verifying
/// signing algorithm validation per OpenID Connect specifications.
/// </summary>
public class SigningAlgorithmsValidatorTests
{
    private readonly Mock<IJsonWebTokenValidator> _jwtValidator;
    private readonly SigningAlgorithmsValidator _validator;

    public SigningAlgorithmsValidatorTests()
    {
        _jwtValidator = new Mock<IJsonWebTokenValidator>(MockBehavior.Strict);
        _validator = new SigningAlgorithmsValidator(_jwtValidator.Object);
    }

    private ClientRegistrationValidationContext CreateContext(
        string? requestObjectSigningAlg = null,
        string? backChannelAuthSigningAlg = null,
        string? tokenEndpointAuthSigningAlg = null)
    {
        var request = new ClientRegistrationRequest
        {
            RedirectUris = [new Uri("https://example.com/callback")],
            RequestObjectSigningAlg = requestObjectSigningAlg,
            BackChannelAuthenticationRequestSigningAlg = backChannelAuthSigningAlg,
            TokenEndpointAuthSigningAlg = tokenEndpointAuthSigningAlg
        };

        return new ClientRegistrationValidationContext(request);
    }

    /// <summary>
    /// Verifies validation succeeds when no signing algorithms specified.
    /// Per OIDC DCR, all signing algorithm parameters are optional.
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
    /// Verifies validation succeeds with supported request object signing algorithm.
    /// Per OIDC Core, request_object_signing_alg must be from supported algorithms.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithSupportedRequestObjectAlg_ShouldReturnNull()
    {
        // Arrange
        _jwtValidator
            .Setup(v => v.SigningAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256, SigningAlgorithms.ES256]);

        var context = CreateContext(requestObjectSigningAlg: SigningAlgorithms.RS256);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error when request object signing algorithm not supported.
    /// Per OIDC Core, only advertised algorithms are allowed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUnsupportedRequestObjectAlg_ShouldReturnError()
    {
        // Arrange
        _jwtValidator
            .Setup(v => v.SigningAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256]);

        var context = CreateContext(requestObjectSigningAlg: SigningAlgorithms.ES256);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("request_object_signing_alg", result.ErrorDescription);
        Assert.Contains("not supported", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies validation succeeds with supported backchannel auth signing algorithm.
    /// Per OIDC CIBA, backchannel_authentication_request_signing_alg must be supported.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithSupportedBackChannelAuthAlg_ShouldReturnNull()
    {
        // Arrange
        _jwtValidator
            .Setup(v => v.SigningAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256, SigningAlgorithms.ES256]);

        var context = CreateContext(backChannelAuthSigningAlg: SigningAlgorithms.ES256);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error when backchannel auth signing algorithm not supported.
    /// Per OIDC CIBA, only provider-supported algorithms allowed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUnsupportedBackChannelAuthAlg_ShouldReturnError()
    {
        // Arrange
        _jwtValidator
            .Setup(v => v.SigningAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256]);

        var context = CreateContext(backChannelAuthSigningAlg: SigningAlgorithms.PS256);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("backchannel_authentication_request_signing_alg", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies validation succeeds with supported token endpoint auth signing algorithm.
    /// Per OIDC Core, token_endpoint_auth_signing_alg must be from supported set.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithSupportedTokenEndpointAuthAlg_ShouldReturnNull()
    {
        // Arrange
        _jwtValidator
            .Setup(v => v.SigningAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256, SigningAlgorithms.ES256]);

        var context = CreateContext(tokenEndpointAuthSigningAlg: SigningAlgorithms.RS256);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error when token endpoint auth signing algorithm not supported.
    /// Per OIDC Core, unsupported algorithms must be rejected.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUnsupportedTokenEndpointAuthAlg_ShouldReturnError()
    {
        // Arrange
        _jwtValidator
            .Setup(v => v.SigningAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256]);

        var context = CreateContext(tokenEndpointAuthSigningAlg: SigningAlgorithms.HS256);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("token_endpoint_auth_signing_alg", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies validation succeeds with all three supported algorithms.
    /// Multiple signing algorithms can be specified simultaneously.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithAllSupportedAlgorithms_ShouldReturnNull()
    {
        // Arrange
        _jwtValidator
            .Setup(v => v.SigningAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256, SigningAlgorithms.ES256, SigningAlgorithms.PS256]);

        var context = CreateContext(
            requestObjectSigningAlg: SigningAlgorithms.RS256,
            backChannelAuthSigningAlg: SigningAlgorithms.ES256,
            tokenEndpointAuthSigningAlg: SigningAlgorithms.PS256);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error stops at first unsupported algorithm.
    /// Validation should fail fast on first error.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithFirstAlgUnsupported_ShouldReturnErrorForFirst()
    {
        // Arrange
        _jwtValidator
            .Setup(v => v.SigningAlgorithmsSupported)
            .Returns([SigningAlgorithms.ES256]);

        var context = CreateContext(
            requestObjectSigningAlg: SigningAlgorithms.RS256, // Unsupported - should fail here
            backChannelAuthSigningAlg: SigningAlgorithms.ES256,
            tokenEndpointAuthSigningAlg: SigningAlgorithms.ES256);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Contains("request_object_signing_alg", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies algorithm comparison is case-sensitive.
    /// Per OAuth 2.0 and JOSE, algorithm names are case-sensitive.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithDifferentCase_ShouldReturnError()
    {
        // Arrange
        _jwtValidator
            .Setup(v => v.SigningAlgorithmsSupported)
            .Returns(["RS256"]);

        var context = CreateContext(requestObjectSigningAlg: "rs256"); // Different case

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies validation with multiple supported algorithms.
    /// Provider may support multiple signing algorithms.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMultipleSupportedAlgs_ShouldValidateCorrectly()
    {
        // Arrange
        _jwtValidator
            .Setup(v => v.SigningAlgorithmsSupported)
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
            requestObjectSigningAlg: SigningAlgorithms.PS512,
            backChannelAuthSigningAlg: SigningAlgorithms.ES384,
            tokenEndpointAuthSigningAlg: SigningAlgorithms.RS256);

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
        _jwtValidator
            .Setup(v => v.SigningAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256]);

        var context = CreateContext(requestObjectSigningAlg: "custom-alg-2024");

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies validator checks provider's supported algorithms.
    /// Ensures proper delegation to JWT validator.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldCheckJwtValidatorAlgorithms()
    {
        // Arrange
        _jwtValidator
            .Setup(v => v.SigningAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256]);

        var context = CreateContext(requestObjectSigningAlg: SigningAlgorithms.RS256);

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        _jwtValidator.Verify(v => v.SigningAlgorithmsSupported, Times.Once);
    }

    /// <summary>
    /// Verifies validation succeeds with none algorithm.
    /// Per OAuth 2.0, \"none\" may be supported for unsigned JWTs.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoneAlgorithm_ShouldValidate()
    {
        // Arrange
        _jwtValidator
            .Setup(v => v.SigningAlgorithmsSupported)
            .Returns([SigningAlgorithms.None, SigningAlgorithms.RS256]);

        var context = CreateContext(requestObjectSigningAlg: SigningAlgorithms.None);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error when none algorithm not explicitly supported.
    /// Provider must explicitly advertise \"none\" if accepting unsigned JWTs.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoneAlgNotSupported_ShouldReturnError()
    {
        // Arrange
        _jwtValidator
            .Setup(v => v.SigningAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256]);

        var context = CreateContext(requestObjectSigningAlg: SigningAlgorithms.None);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }
}
