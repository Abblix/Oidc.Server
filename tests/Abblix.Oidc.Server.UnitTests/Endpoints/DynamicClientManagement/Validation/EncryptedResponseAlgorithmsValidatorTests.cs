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
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Unit tests for <see cref="EncryptedResponseAlgorithmsValidator"/> verifying that the JWE algorithms a client
/// registers for encrypted ID tokens, UserInfo responses, request objects and JARM authorization responses are
/// checked against the server's supported key-management (<c>alg</c>) and content-encryption (<c>enc</c>) sets.
/// </summary>
public class EncryptedResponseAlgorithmsValidatorTests
{
    private const string SupportedAlg = EncryptionAlgorithms.KeyManagement.RsaOaep256;
    private const string SupportedEnc = EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256;

    private readonly Mock<IJsonWebTokenValidator> _jwtValidator = new(MockBehavior.Strict);
    private readonly EncryptedResponseAlgorithmsValidator _validator;

    public EncryptedResponseAlgorithmsValidatorTests()
    {
        _jwtValidator.Setup(v => v.EncryptionAlgorithmsSupported).Returns([SupportedAlg]);
        _jwtValidator.Setup(v => v.EncryptionMethodsSupported).Returns([SupportedEnc]);
        _validator = new EncryptedResponseAlgorithmsValidator(_jwtValidator.Object);
    }

    private static ClientRegistrationValidationContext CreateContext(ClientRegistrationRequest request)
        => new(request);

    private static ClientRegistrationRequest Request()
        => new() { RedirectUris = [TestConstants.DefaultRedirectUri] };

    [Fact]
    public async Task ValidateAsync_WithNoAlgorithms_ShouldReturnNull()
    {
        var result = await _validator.ValidateAsync(CreateContext(Request()));
        Assert.Null(result);
    }

    [Fact]
    public async Task ValidateAsync_WithSupportedAlgorithmsForEveryField_ShouldReturnNull()
    {
        var request = Request() with
        {
            IdTokenEncryptedResponseAlg = SupportedAlg,
            IdTokenEncryptedResponseEnc = SupportedEnc,
            UserInfoEncryptedResponseAlg = SupportedAlg,
            UserInfoEncryptedResponseEnc = SupportedEnc,
            IntrospectionEncryptedResponseAlg = SupportedAlg,
            IntrospectionEncryptedResponseEnc = SupportedEnc,
            RequestObjectEncryptionAlg = SupportedAlg,
            RequestObjectEncryptionEnc = SupportedEnc,
            AuthorizationEncryptedResponseAlg = SupportedAlg,
            AuthorizationEncryptedResponseEnc = SupportedEnc,
        };

        var result = await _validator.ValidateAsync(CreateContext(request));

        Assert.Null(result);
    }

    [Theory]
    [InlineData(ClientRegistrationRequest.Parameters.IdTokenEncryptedResponseAlg)]
    [InlineData(ClientRegistrationRequest.Parameters.UserInfoEncryptedResponseAlg)]
    [InlineData(ClientRegistrationRequest.Parameters.IntrospectionEncryptedResponseAlg)]
    [InlineData(ClientRegistrationRequest.Parameters.RequestObjectEncryptionAlg)]
    [InlineData(ClientRegistrationRequest.Parameters.AuthorizationEncryptedResponseAlg)]
    public async Task ValidateAsync_WithUnsupportedKeyManagementAlg_ShouldReturnError(string wireName)
    {
        const string unsupported = EncryptionAlgorithms.KeyManagement.Rsa1_5;
        var request = wireName switch
        {
            ClientRegistrationRequest.Parameters.IdTokenEncryptedResponseAlg => Request() with { IdTokenEncryptedResponseAlg = unsupported },
            ClientRegistrationRequest.Parameters.UserInfoEncryptedResponseAlg => Request() with { UserInfoEncryptedResponseAlg = unsupported },
            ClientRegistrationRequest.Parameters.IntrospectionEncryptedResponseAlg => Request() with { IntrospectionEncryptedResponseAlg = unsupported },
            ClientRegistrationRequest.Parameters.RequestObjectEncryptionAlg => Request() with { RequestObjectEncryptionAlg = unsupported },
            _ => Request() with { AuthorizationEncryptedResponseAlg = unsupported },
        };

        var result = await _validator.ValidateAsync(CreateContext(request));

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains(wireName, result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateAsync_WithUnsupportedContentEncryption_ShouldReturnError()
    {
        var request = Request() with
        {
            AuthorizationEncryptedResponseAlg = SupportedAlg,
            AuthorizationEncryptedResponseEnc = EncryptionAlgorithms.ContentEncryption.Aes256Gcm,
        };

        var result = await _validator.ValidateAsync(CreateContext(request));

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains(ClientRegistrationRequest.Parameters.AuthorizationEncryptedResponseEnc, result.ErrorDescription);
    }
}
