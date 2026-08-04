// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/Oidc.Server. All development and modifications
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

using System.Linq;

using Abblix.Jwt;
using Abblix.Oidc.Server.Endpoints.Configuration;
using Abblix.Oidc.Server.Features.DPoP;

using Moq;

using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Configuration;

/// <summary>
/// Unit tests for <see cref="JwtAlgorithmsProvider"/>. The provider proxies creator/validator
/// algorithm sets unchanged for the existing pair (id-token / userinfo signing); the new
/// <see cref="JwtAlgorithmsProvider.DpopSigningAlgorithmsSupported"/> property intersects the
/// validator side with the static <see cref="DPoPAlgorithms.Allowed"/> whitelist (RFC 9449 §5.1).
/// </summary>
public class JwtAlgorithmsProviderTests
{
    private readonly Mock<IJsonWebTokenCreator> _creator = new(MockBehavior.Strict);
    private readonly Mock<IJsonWebTokenValidator> _validator = new(MockBehavior.Strict);

    private JwtAlgorithmsProvider CreateProvider() => new(_creator.Object, _validator.Object);

    [Fact]
    public void DpopSigningAlgorithmsSupported_ValidatorReturnsNothingInWhitelist_ReturnsEmpty()
    {
        // Validator supports only an HMAC alg the DPoP whitelist deliberately excludes.
        _validator.Setup(v => v.SigningAlgorithmsSupported).Returns(["HS256"]);

        var result = CreateProvider().DpopSigningAlgorithmsSupported.ToArray();

        Assert.Empty(result);
    }

    [Fact]
    public void DpopSigningAlgorithmsSupported_ValidatorReturnsFullWhitelist_ReturnsFullWhitelist()
    {
        // Order-independent: assert set equality.
        _validator.Setup(v => v.SigningAlgorithmsSupported).Returns(DPoPAlgorithms.Allowed);

        var result = CreateProvider().DpopSigningAlgorithmsSupported.ToArray();

        Assert.Equal(
            DPoPAlgorithms.Allowed.OrderBy(a => a),
            result.OrderBy(a => a));
    }

    [Fact]
    public void DpopSigningAlgorithmsSupported_PartialOverlap_ReturnsOnlyIntersection()
    {
        // RS256 / ES256 are in the whitelist; HS256 is not.
        _validator.Setup(v => v.SigningAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256, "HS256", SigningAlgorithms.ES256]);

        var result = CreateProvider().DpopSigningAlgorithmsSupported.ToArray();

        Assert.Equal(
            new[] { SigningAlgorithms.RS256, SigningAlgorithms.ES256 }.OrderBy(a => a),
            result.OrderBy(a => a));
    }

    [Fact]
    public void RequestObjectEncryptionAlgValuesSupported_ForwardsValidatorKeyManagementAlgorithms()
    {
        string[] keyManagement =
        [
            EncryptionAlgorithms.KeyManagement.RsaOaep256,
            EncryptionAlgorithms.KeyManagement.Aes256Gcmkw,
        ];
        _validator.Setup(v => v.EncryptionAlgorithmsSupported).Returns(keyManagement);

        var result = CreateProvider().RequestObjectEncryptionAlgValuesSupported.ToArray();

        Assert.Equal(keyManagement, result);
    }

    [Fact]
    public void RequestObjectEncryptionEncValuesSupported_ForwardsValidatorContentEncryptionAlgorithms()
    {
        string[] contentEncryption =
        [
            EncryptionAlgorithms.ContentEncryption.Aes256Gcm,
            EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256,
        ];
        _validator.Setup(v => v.EncryptionMethodsSupported).Returns(contentEncryption);

        var result = CreateProvider().RequestObjectEncryptionEncValuesSupported.ToArray();

        Assert.Equal(contentEncryption, result);
    }

    [Fact]
    public void AuthorizationSigningAlgValuesSupported_ForwardsCreatorSignedResponseAlgorithms()
    {
        // JARM responses are signed with the same service keys as ID tokens - the creator's signing set.
        string[] signing = [SigningAlgorithms.RS256, SigningAlgorithms.ES256];
        _creator.Setup(c => c.SignedResponseAlgorithmsSupported).Returns(signing);

        var result = CreateProvider().AuthorizationSigningAlgValuesSupported.ToArray();

        Assert.Equal(signing, result);
    }

    /// <summary>
    /// OIDC Core §10.1: HS* signatures key on the client_secret, which this server stores only as
    /// a hash - so HMAC algorithms must not be advertised on any client-addressed response-signing
    /// list, even when the JWT layer has HMAC signers registered. Previously the full signer set
    /// (HS* included) leaked into discovery, a client could register HS256 via DCR, and the first
    /// issued id_token failed with a server error at signing-key lookup.
    /// </summary>
    [Fact]
    public void ClientAddressedSigningLists_ExcludeHmacAlgorithms()
    {
        _creator.Setup(c => c.SignedResponseAlgorithmsSupported).Returns(
        [
            SigningAlgorithms.RS256, SigningAlgorithms.ES256,
            SigningAlgorithms.HS256, SigningAlgorithms.HS384, SigningAlgorithms.HS512,
        ]);
        var provider = CreateProvider();

        string[] expected = [SigningAlgorithms.RS256, SigningAlgorithms.ES256];
        Assert.Equal(expected, provider.SignedResponseAlgorithmsSupported.ToArray());
        Assert.Equal(expected, provider.AuthorizationSigningAlgValuesSupported.ToArray());
        Assert.Equal(expected, provider.IntrospectionSigningAlgValuesSupported.ToArray());
    }

    [Fact]
    public void AuthorizationEncryptionAlgValuesSupported_ForwardsValidatorKeyManagementAlgorithms()
    {
        string[] keyManagement = [EncryptionAlgorithms.KeyManagement.RsaOaep256];
        _validator.Setup(v => v.EncryptionAlgorithmsSupported).Returns(keyManagement);

        var result = CreateProvider().AuthorizationEncryptionAlgValuesSupported.ToArray();

        Assert.Equal(keyManagement, result);
    }

    [Fact]
    public void AuthorizationEncryptionEncValuesSupported_ForwardsValidatorContentEncryptionAlgorithms()
    {
        string[] contentEncryption = [EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256];
        _validator.Setup(v => v.EncryptionMethodsSupported).Returns(contentEncryption);

        var result = CreateProvider().AuthorizationEncryptionEncValuesSupported.ToArray();

        Assert.Equal(contentEncryption, result);
    }
    /// <summary>
    /// RFC 8414 §2 / OIDC Discovery 1.0 §3: token_endpoint_auth_signing_alg_values_supported MUST
    /// NOT contain "none". HS* stay because client_secret_jwt keys on the client secret.
    /// </summary>
    [Fact]
    public void TokenEndpointAuthSigningAlgValuesSupported_ExcludesNone_KeepsHmac()
    {
        _validator.Setup(v => v.SigningAlgorithmsSupported).Returns(
            [SigningAlgorithms.None, SigningAlgorithms.RS256, SigningAlgorithms.HS256]);

        var result = CreateProvider().TokenEndpointAuthSigningAlgValuesSupported.ToArray();

        Assert.DoesNotContain(SigningAlgorithms.None, result);
        Assert.Contains(SigningAlgorithms.RS256, result);
        Assert.Contains(SigningAlgorithms.HS256, result);
    }

    /// <summary>
    /// CIBA Core §7.1.1 requires an asymmetric signature, so
    /// backchannel_authentication_request_signing_alg_values_supported excludes "none" and every HS*.
    /// </summary>
    [Fact]
    public void BackChannelAuthenticationRequestSigningAlgValuesSupported_ExcludesNoneAndHmac()
    {
        _validator.Setup(v => v.SigningAlgorithmsSupported).Returns(
        [
            SigningAlgorithms.None,
            SigningAlgorithms.RS256, SigningAlgorithms.ES256,
            SigningAlgorithms.HS256, SigningAlgorithms.HS384, SigningAlgorithms.HS512,
        ]);

        var result = CreateProvider().BackChannelAuthenticationRequestSigningAlgValuesSupported.ToArray();

        Assert.Equal(
            new[] { SigningAlgorithms.RS256, SigningAlgorithms.ES256 }.OrderBy(a => a),
            result.OrderBy(a => a));
    }
}
