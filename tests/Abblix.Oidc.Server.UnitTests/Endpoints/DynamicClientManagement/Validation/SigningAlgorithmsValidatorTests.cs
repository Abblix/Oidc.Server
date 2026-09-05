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
/// Unit tests for <see cref="SigningAlgorithmsValidator"/> verifying
/// signing algorithm validation per OpenID Connect specifications.
/// </summary>
public class SigningAlgorithmsValidatorTests
{
    private readonly Mock<IJwtAlgorithmsProvider> _jwtAlgorithms;
    private readonly SigningAlgorithmsValidator _validator;

    public SigningAlgorithmsValidatorTests()
    {
        _jwtAlgorithms = new Mock<IJwtAlgorithmsProvider>(MockBehavior.Strict);
        _validator = new SigningAlgorithmsValidator(_jwtAlgorithms.Object);
    }

    private ClientRegistrationValidationContext CreateContext(
        string? requestObjectSigningAlg = null,
        string? backChannelAuthSigningAlg = null,
        string? tokenEndpointAuthSigningAlg = null)
    {
        var request = new ClientRegistrationRequest
        {
            RedirectUris = [TestConstants.DefaultRedirectUri],
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
        var context = CreateContext();

        var result = await _validator.ValidateAsync(context);

        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with supported request object signing algorithm.
    /// Per OIDC Core, request_object_signing_alg must be from supported algorithms.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithSupportedRequestObjectAlg_ShouldReturnNull()
    {
        _jwtAlgorithms
            .Setup(p => p.SigningAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256, SigningAlgorithms.ES256]);

        var context = CreateContext(requestObjectSigningAlg: SigningAlgorithms.RS256);

        var result = await _validator.ValidateAsync(context);

        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error when request object signing algorithm not supported.
    /// Per OIDC Core, only advertised algorithms are allowed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUnsupportedRequestObjectAlg_ShouldReturnError()
    {
        _jwtAlgorithms
            .Setup(p => p.SigningAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256]);

        var context = CreateContext(requestObjectSigningAlg: SigningAlgorithms.ES256);

        var result = await _validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("request_object_signing_alg", result.ErrorDescription);
        Assert.Contains("not supported", result.ErrorDescription);
    }

    /// <summary>
    /// request_object_signing_alg may be "none" (OIDC Core §6.1 - unsigned request objects delivered
    /// over TLS), so it stays acceptable when the server advertises it.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoneRequestObjectAlg_ShouldReturnNull()
    {
        _jwtAlgorithms
            .Setup(p => p.SigningAlgorithmsSupported)
            .Returns([SigningAlgorithms.None, SigningAlgorithms.RS256]);

        var context = CreateContext(requestObjectSigningAlg: SigningAlgorithms.None);

        var result = await _validator.ValidateAsync(context);

        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error when request_object_signing_alg="none" is not advertised.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoneRequestObjectAlgNotSupported_ShouldReturnError()
    {
        _jwtAlgorithms
            .Setup(p => p.SigningAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256]);

        var context = CreateContext(requestObjectSigningAlg: SigningAlgorithms.None);

        var result = await _validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies validation succeeds with supported backchannel auth signing algorithm.
    /// Per OIDC CIBA, backchannel_authentication_request_signing_alg must be supported.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithSupportedBackChannelAuthAlg_ShouldReturnNull()
    {
        _jwtAlgorithms
            .Setup(p => p.BackChannelAuthenticationRequestSigningAlgValuesSupported)
            .Returns([SigningAlgorithms.RS256, SigningAlgorithms.ES256]);

        var context = CreateContext(backChannelAuthSigningAlg: SigningAlgorithms.ES256);

        var result = await _validator.ValidateAsync(context);

        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error when backchannel auth signing algorithm not supported.
    /// Per OIDC CIBA, only provider-supported algorithms allowed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUnsupportedBackChannelAuthAlg_ShouldReturnError()
    {
        _jwtAlgorithms
            .Setup(p => p.BackChannelAuthenticationRequestSigningAlgValuesSupported)
            .Returns([SigningAlgorithms.RS256]);

        var context = CreateContext(backChannelAuthSigningAlg: SigningAlgorithms.PS256);

        var result = await _validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("backchannel_authentication_request_signing_alg", result.ErrorDescription);
    }

    /// <summary>
    /// CIBA Core §7.1.1: "none" is not a valid backchannel_authentication_request_signing_alg -
    /// the filtered set excludes it, so registration is rejected.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoneBackChannelAuthAlg_ShouldReturnError()
    {
        _jwtAlgorithms
            .Setup(p => p.BackChannelAuthenticationRequestSigningAlgValuesSupported)
            .Returns([SigningAlgorithms.RS256, SigningAlgorithms.ES256]);

        var context = CreateContext(backChannelAuthSigningAlg: SigningAlgorithms.None);

        var result = await _validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("backchannel_authentication_request_signing_alg", result.ErrorDescription);
    }

    /// <summary>
    /// CIBA Core §7.1.1 requires an asymmetric signature - a symmetric HS* value is rejected because
    /// it is not a member of the filtered backchannel set.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithHmacBackChannelAuthAlg_ShouldReturnError()
    {
        _jwtAlgorithms
            .Setup(p => p.BackChannelAuthenticationRequestSigningAlgValuesSupported)
            .Returns([SigningAlgorithms.RS256, SigningAlgorithms.ES256]);

        var context = CreateContext(backChannelAuthSigningAlg: SigningAlgorithms.HS256);

        var result = await _validator.ValidateAsync(context);

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
        _jwtAlgorithms
            .Setup(p => p.TokenEndpointAuthSigningAlgValuesSupported)
            .Returns([SigningAlgorithms.RS256, SigningAlgorithms.ES256]);

        var context = CreateContext(tokenEndpointAuthSigningAlg: SigningAlgorithms.RS256);

        var result = await _validator.ValidateAsync(context);

        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error when token endpoint auth signing algorithm not supported.
    /// Per OIDC Core, unsupported algorithms must be rejected.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUnsupportedTokenEndpointAuthAlg_ShouldReturnError()
    {
        _jwtAlgorithms
            .Setup(p => p.TokenEndpointAuthSigningAlgValuesSupported)
            .Returns([SigningAlgorithms.RS256]);

        var context = CreateContext(tokenEndpointAuthSigningAlg: SigningAlgorithms.ES256);

        var result = await _validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("token_endpoint_auth_signing_alg", result.ErrorDescription);
    }

    /// <summary>
    /// RFC 8414 §2 / OIDC Discovery 1.0 §3: "none" is not a valid token_endpoint_auth_signing_alg -
    /// the filtered set excludes it, so registration is rejected.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoneTokenEndpointAuthAlg_ShouldReturnError()
    {
        _jwtAlgorithms
            .Setup(p => p.TokenEndpointAuthSigningAlgValuesSupported)
            .Returns([SigningAlgorithms.RS256, SigningAlgorithms.HS256]);

        var context = CreateContext(tokenEndpointAuthSigningAlg: SigningAlgorithms.None);

        var result = await _validator.ValidateAsync(context);

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
        _jwtAlgorithms
            .Setup(p => p.SigningAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256, SigningAlgorithms.ES256, SigningAlgorithms.PS256]);
        _jwtAlgorithms
            .Setup(p => p.BackChannelAuthenticationRequestSigningAlgValuesSupported)
            .Returns([SigningAlgorithms.RS256, SigningAlgorithms.ES256, SigningAlgorithms.PS256]);
        _jwtAlgorithms
            .Setup(p => p.TokenEndpointAuthSigningAlgValuesSupported)
            .Returns([SigningAlgorithms.RS256, SigningAlgorithms.ES256, SigningAlgorithms.PS256]);

        var context = CreateContext(
            requestObjectSigningAlg: SigningAlgorithms.RS256,
            backChannelAuthSigningAlg: SigningAlgorithms.ES256,
            tokenEndpointAuthSigningAlg: SigningAlgorithms.PS256);

        var result = await _validator.ValidateAsync(context);

        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error stops at first unsupported algorithm.
    /// Validation should fail fast on first error (request object checked first).
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithFirstAlgUnsupported_ShouldReturnErrorForFirst()
    {
        _jwtAlgorithms
            .Setup(p => p.SigningAlgorithmsSupported)
            .Returns([SigningAlgorithms.ES256]);

        var context = CreateContext(
            requestObjectSigningAlg: SigningAlgorithms.RS256,
            backChannelAuthSigningAlg: SigningAlgorithms.ES256,
            tokenEndpointAuthSigningAlg: SigningAlgorithms.ES256);

        var result = await _validator.ValidateAsync(context);

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
        _jwtAlgorithms
            .Setup(p => p.SigningAlgorithmsSupported)
            .Returns(["RS256"]);

        var context = CreateContext(requestObjectSigningAlg: "rs256");

        var result = await _validator.ValidateAsync(context);

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
        string[] asymmetric =
        [
            SigningAlgorithms.RS256, SigningAlgorithms.RS384, SigningAlgorithms.RS512,
            SigningAlgorithms.ES256, SigningAlgorithms.ES384, SigningAlgorithms.ES512,
            SigningAlgorithms.PS256, SigningAlgorithms.PS384, SigningAlgorithms.PS512
        ];
        _jwtAlgorithms.Setup(p => p.SigningAlgorithmsSupported).Returns(asymmetric);
        _jwtAlgorithms.Setup(p => p.BackChannelAuthenticationRequestSigningAlgValuesSupported).Returns(asymmetric);
        _jwtAlgorithms.Setup(p => p.TokenEndpointAuthSigningAlgValuesSupported).Returns(asymmetric);

        var context = CreateContext(
            requestObjectSigningAlg: SigningAlgorithms.PS512,
            backChannelAuthSigningAlg: SigningAlgorithms.ES384,
            tokenEndpointAuthSigningAlg: SigningAlgorithms.RS256);

        var result = await _validator.ValidateAsync(context);

        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation with custom/unknown algorithm.
    /// Only JOSE standard or provider-specific advertised algorithms allowed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithCustomAlgorithm_ShouldReturnError()
    {
        _jwtAlgorithms
            .Setup(p => p.SigningAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256]);

        var context = CreateContext(requestObjectSigningAlg: "custom-alg-2024");

        var result = await _validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies validator checks the provider's supported algorithms.
    /// Ensures proper delegation to the algorithms provider.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldCheckJwtAlgorithms()
    {
        _jwtAlgorithms
            .Setup(p => p.SigningAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256]);

        var context = CreateContext(requestObjectSigningAlg: SigningAlgorithms.RS256);

        await _validator.ValidateAsync(context);

        _jwtAlgorithms.Verify(p => p.SigningAlgorithmsSupported, Times.Once);
    }
}
