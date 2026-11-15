// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Options;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Common.Configuration;
using System;
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

    private static readonly Uri JwksUri = new("https://client.example.com/jwks");

    private readonly Mock<IJsonWebTokenValidator> _jwtValidator = new(MockBehavior.Strict);
    private readonly Mock<IClientInfoProvider> _clientInfoProvider = new(MockBehavior.Strict);
    private readonly EncryptedResponseAlgorithmsValidator _validator;

    public EncryptedResponseAlgorithmsValidatorTests()
    {
        _jwtValidator.Setup(v => v.EncryptionAlgorithmsSupported).Returns(
        [
            SupportedAlg,
            EncryptionAlgorithms.KeyManagement.Aes128KW,
            EncryptionAlgorithms.KeyManagement.Dir,
            EncryptionAlgorithms.KeyManagement.Pbes2HmacSha256Aes128KW,
        ]);
        _jwtValidator.Setup(v => v.EncryptionMethodsSupported).Returns([SupportedEnc]);
        _validator = new EncryptedResponseAlgorithmsValidator(
            _jwtValidator.Object,
            Options.Create(new OidcOptions()),
            _clientInfoProvider.Object,
            TimeProvider.System);
    }

    private static ClientRegistrationValidationContext CreateContext(ClientRegistrationRequest request)
        => new(request);

    private static ClientRegistrationRequest Request()
        => new() { RedirectUris = [TestConstants.DefaultRedirectUri], JwksUri = JwksUri };

    [Fact]
    public async Task ValidateAsync_WithNoAlgorithms_ShouldReturnNull()
    {
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, CreateContext(Request()));
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

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, CreateContext(request));

        Assert.Null(result);
    }

    /// <summary>
    /// RFC 7591 section 3.2.2: an algorithm the server does not support is a client metadata value it rejects, answered
    /// with <c>invalid_client_metadata</c> rather than <c>invalid_request</c>.
    /// </summary>
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

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, CreateContext(request));

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
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

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, CreateContext(request));

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Contains(ClientRegistrationRequest.Parameters.AuthorizationEncryptedResponseEnc, result.ErrorDescription);
    }

    /// <summary>The request registering <paramref name="algorithm"/> for the JWT <paramref name="wireName"/> names.</summary>
    private static ClientRegistrationRequest Registering(ClientRegistrationRequest request, string wireName, string algorithm)
        => wireName switch
        {
            ClientRegistrationRequest.Parameters.IdTokenEncryptedResponseAlg => request with { IdTokenEncryptedResponseAlg = algorithm },
            ClientRegistrationRequest.Parameters.UserInfoEncryptedResponseAlg => request with { UserInfoEncryptedResponseAlg = algorithm },
            ClientRegistrationRequest.Parameters.IntrospectionEncryptedResponseAlg => request with { IntrospectionEncryptedResponseAlg = algorithm },
            ClientRegistrationRequest.Parameters.AuthorizationEncryptedResponseAlg => request with { AuthorizationEncryptedResponseAlg = algorithm },
            ClientRegistrationRequest.Parameters.RequestObjectEncryptionAlg => request with { RequestObjectEncryptionAlg = algorithm },
            _ => throw new ArgumentOutOfRangeException(nameof(wireName), wireName, null),
        };

    /// <summary>
    /// OpenID Connect Core 1.0 section 10.2: an asymmetric algorithm encrypts to "a public key used for encryption
    /// published by the recipient in its JWK Set document", so a client registering one for a JWT this server sends,
    /// with neither jwks nor jwks_uri, could never be sent it and is refused; a request object is encrypted by the
    /// client to a key of this server, and is not.
    /// </summary>
    [Theory]
    [InlineData(ClientRegistrationRequest.Parameters.IdTokenEncryptedResponseAlg, ErrorCodes.InvalidClientMetadata)]
    [InlineData(ClientRegistrationRequest.Parameters.UserInfoEncryptedResponseAlg, ErrorCodes.InvalidClientMetadata)]
    [InlineData(ClientRegistrationRequest.Parameters.IntrospectionEncryptedResponseAlg, ErrorCodes.InvalidClientMetadata)]
    [InlineData(ClientRegistrationRequest.Parameters.AuthorizationEncryptedResponseAlg, ErrorCodes.InvalidClientMetadata)]
    [InlineData(ClientRegistrationRequest.Parameters.RequestObjectEncryptionAlg, null)]
    public async Task ValidateAsync_AnAsymmetricAlgorithmWithNoKeySet_IsRefused(string wireName, string? expected)
    {
        var request = Registering(Request() with { JwksUri = null }, wireName, SupportedAlg);

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, CreateContext(request));

        Assert.Equal(expected, result?.Error);
    }

    /// <summary>
    /// A key set passed by value changes only by a registration, so it is judged here: it serves the algorithm when it
    /// holds an encryption key that carries it, and not when it is empty, holds signing keys alone, or keys of another
    /// type or algorithm.
    /// </summary>
    [Theory]
    [InlineData("rsa encryption", null)]
    [InlineData("rsa for the algorithm", null)]
    [InlineData("empty", ErrorCodes.InvalidClientMetadata)]
    [InlineData("rsa signature", ErrorCodes.InvalidClientMetadata)]
    [InlineData("ec encryption", ErrorCodes.InvalidClientMetadata)]
    [InlineData("rsa for another algorithm", ErrorCodes.InvalidClientMetadata)]
    public async Task ValidateAsync_AnAsymmetricAlgorithmWithAKeySetByValue_IsJudgedByItsKeys(string keys, string? expected)
    {
        JsonWebKey[] set = keys switch
        {
            "rsa encryption" => [new RsaJsonWebKey { Usage = PublicKeyUsages.Encryption }],
            "rsa for the algorithm" => [new RsaJsonWebKey { Algorithm = SupportedAlg }],
            "empty" => [],
            "rsa signature" => [new RsaJsonWebKey { Usage = PublicKeyUsages.Signature }],
            "ec encryption" => [new EllipticCurveJsonWebKey { Usage = PublicKeyUsages.Encryption }],
            "rsa for another algorithm" => [new RsaJsonWebKey { Algorithm = EncryptionAlgorithms.KeyManagement.RsaOaep }],
            _ => throw new ArgumentOutOfRangeException(nameof(keys), keys, null),
        };
        var request = Request() with
        {
            JwksUri = null,
            Jwks = new JsonWebKeySet(set),
            IdTokenEncryptedResponseAlg = SupportedAlg,
        };

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, CreateContext(request));

        Assert.Equal(expected, result?.Error);
    }

    /// <summary>
    /// OpenID Connect Core 1.0 section 10.2: a symmetric key is "derived from the client_secret value", so it is served
    /// only where the server keeps the secret itself - for client_secret_jwt - and never for a public client ("Symmetric
    /// encryption MUST NOT be used by public (non-confidential) Clients"); a secret kept only as its hash serves none.
    /// </summary>
    [Theory]
    [InlineData(EncryptionAlgorithms.KeyManagement.Aes128KW, ClientAuthenticationMethods.ClientSecretJwt, null)]
    [InlineData(EncryptionAlgorithms.KeyManagement.Dir, ClientAuthenticationMethods.ClientSecretJwt, null)]
    [InlineData(EncryptionAlgorithms.KeyManagement.Aes128KW, ClientAuthenticationMethods.ClientSecretBasic, ErrorCodes.InvalidClientMetadata)]
    [InlineData(EncryptionAlgorithms.KeyManagement.Dir, ClientAuthenticationMethods.ClientSecretPost, ErrorCodes.InvalidClientMetadata)]
    [InlineData(EncryptionAlgorithms.KeyManagement.Aes128KW, ClientAuthenticationMethods.PrivateKeyJwt, ErrorCodes.InvalidClientMetadata)]
    [InlineData(EncryptionAlgorithms.KeyManagement.Aes128KW, ClientAuthenticationMethods.None, ErrorCodes.InvalidClientMetadata)]
    public async Task ValidateAsync_ASymmetricAlgorithm_IsAcceptedOnlyWhereTheSecretIsKept(
        string algorithm, string authenticationMethod, string? expected)
    {
        var request = Request() with
        {
            JwksUri = null,
            TokenEndpointAuthMethod = authenticationMethod,
            UserInfoEncryptedResponseAlg = algorithm,
        };

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, CreateContext(request));

        Assert.Equal(expected, result?.Error);
    }

    /// <summary>
    /// Section 10.2 derives a key "for the AES key wrapping or direct encryption algorithm used" and for nothing else,
    /// so a password-based algorithm has no key, whatever the client authenticates with.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_APasswordBasedAlgorithm_IsRefused()
    {
        var request = Request() with
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretJwt,
            IdTokenEncryptedResponseAlg = EncryptionAlgorithms.KeyManagement.Pbes2HmacSha256Aes128KW,
        };

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, CreateContext(request));

        Assert.Equal(ErrorCodes.InvalidClientMetadata, result?.Error);
    }

    /// <summary>
    /// RFC 7592 section 2.2 keeps the client's secrets across an update, so a symmetric algorithm registered by one is
    /// judged by the secret the stored client holds: served where it holds the secret itself, not where it holds only
    /// the hash, nor where the update makes it a public client.
    /// </summary>
    [Theory]
    [InlineData(true, ClientAuthenticationMethods.ClientSecretJwt, null)]
    [InlineData(true, ClientAuthenticationMethods.ClientSecretBasic, null)]
    [InlineData(false, ClientAuthenticationMethods.ClientSecretJwt, ErrorCodes.InvalidClientMetadata)]
    [InlineData(true, ClientAuthenticationMethods.None, ErrorCodes.InvalidClientMetadata)]
    public async Task ValidateAsync_ASymmetricAlgorithmOnUpdate_IsJudgedByTheStoredSecret(
        bool secretKept, string authenticationMethod, string? expected)
    {
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, TestConstants.DefaultClientId))
            .ReturnsAsync(new ClientInfo(TestConstants.DefaultClientId)
            {
                ClientSecrets = [new ClientSecret { Sha512Hash = [1], Value = secretKept ? "a-client-secret" : null }],
            });
        var request = Request() with
        {
            ClientId = TestConstants.DefaultClientId,
            TokenEndpointAuthMethod = authenticationMethod,
            AuthorizationEncryptedResponseAlg = EncryptionAlgorithms.KeyManagement.Aes128KW,
        };

        var result = await _validator.ValidateAsync(
            SingleIssuer.Tenant, CreateContext(request) with { Operation = DynamicClientOperation.Update });

        Assert.Equal(expected, result?.Error);
    }
}
