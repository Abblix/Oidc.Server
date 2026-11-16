// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Jwt.Encryption;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;
using static Abblix.Jwt.EncryptionAlgorithms;

namespace Abblix.Oidc.Server.UnitTests.Features.Tokens.Formatters;

/// <summary>
/// Unit tests for <see cref="ClientEncryptionKeyResolver"/>: the key a client-addressed JWT is encrypted to under the
/// algorithm the client registered, published by the client for an asymmetric algorithm and derived from its secret
/// for a symmetric one (OpenID Connect Core 1.0 section 10.2).
/// </summary>
public class ClientEncryptionKeyResolverTests
{
    private const string ClientSecret = "GfSpzT3oVvYx8qWk2LmN7bR4cJ9dH6eA";

    /// <summary>The name a host registers an RSA key management algorithm of its own under.</summary>
    private const string HostRsaAlgorithm = "X-HOST-RSA";

    private static readonly DateTimeOffset Now = new(2026, 11, 15, 12, 0, 0, TimeSpan.Zero);

    private static readonly SecurityProfileRequirements NoProfile = SecurityProfileRequirements.Resolve(ClientSecurityProfile.None);

    private readonly Mock<IClientKeysProvider> _clientKeys = new(MockBehavior.Strict);

    /// <summary>
    /// Every key management algorithm the library carries and one a host registers for RSA keys under its own name.
    /// </summary>
    private static readonly EncryptionAlgorithmsProvider Algorithms = TestEncryptionAlgorithms.With(services => services
        .AddRsaPkcs1KeyManagement()
        .AddPbes2KeyManagement()
        .AddKeyedSingleton<IKeyManagementAlgorithm<RsaJsonWebKey>>(
            HostRsaAlgorithm,
            (serviceProvider, _) => serviceProvider.GetRequiredKeyedService<IKeyManagementAlgorithm<RsaJsonWebKey>>(
                KeyManagement.RsaOaep256)));

    private ClientEncryptionKeyResolver Resolver(IJsonWebTokenCreator? creator = null)
        => new(
            new ProfiledJwtIssuer(creator ?? EveryAlgorithm(), Algorithms),
            _clientKeys.Object,
            new FakeTimeProvider(Now),
            Algorithms);

    private static IJsonWebTokenCreator EveryAlgorithm()
    {
        var creator = new Mock<IJsonWebTokenCreator>(MockBehavior.Strict);
        creator.Setup(c => c.EncryptedResponseAlgorithmsSupported).Returns(
        [
            KeyManagement.RsaOaep256, KeyManagement.Aes128KW, KeyManagement.Aes192KW, KeyManagement.Aes256KW,
            KeyManagement.Aes128Gcmkw, KeyManagement.Dir, KeyManagement.Pbes2HmacSha256Aes128KW,
        ]);
        return creator.Object;
    }

    private static ClientInfo ClientHolding(params ClientSecret[] secrets) => new(TestConstants.DefaultClientId)
    {
        TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretJwt,
        ClientSecrets = secrets,
    };

    /// <summary>
    /// Section 10.2: the left-most bits of SHA-256 of the UTF-8 client_secret for a key of up to 256 bits, of SHA-384 up
    /// to 384 and of SHA-512 up to 512, truncated "to the appropriate bit length for the AES key wrapping or direct
    /// encryption algorithm used"; under dir that is the content encryption key. The expected keys are digests of the
    /// secret computed outside this library.
    /// </summary>
    [Theory]
    [InlineData(KeyManagement.Aes128KW, ContentEncryption.Aes256CbcHmacSha512, "EE295520A9FF3D46618AF0828E11935E")]
    [InlineData(KeyManagement.Aes128Gcmkw, ContentEncryption.Aes128CbcHmacSha256, "EE295520A9FF3D46618AF0828E11935E")]
    [InlineData(KeyManagement.Aes192KW, ContentEncryption.Aes128CbcHmacSha256,
        "EE295520A9FF3D46618AF0828E11935EF581020690836B6A")]
    [InlineData(KeyManagement.Dir, ContentEncryption.Aes128Gcm, "EE295520A9FF3D46618AF0828E11935E")]
    [InlineData(KeyManagement.Dir, ContentEncryption.Aes128CbcHmacSha256,
        "EE295520A9FF3D46618AF0828E11935EF581020690836B6A1F5CA2BFFEDFE95A")]
    [InlineData(KeyManagement.Dir, ContentEncryption.Aes192CbcHmacSha384,
        "EB773F24429662386DCD35CFB72FA7548BBF6530AF952D29BFB5728C22713D89A7624937D4C48F57A0B82EDDF35F53EF")]
    [InlineData(KeyManagement.Dir, ContentEncryption.Aes256CbcHmacSha512,
        "019AA45FBBB44B5C152DB85E0DB7B2C778F8F31CB0622B8AD3B181407C1AD440A9B54BAB223E250C403F0A8565E0EA6CA297D2B0B05E008FE4224512ECDEAD73")]
    public async Task ASymmetricAlgorithm_EncryptsToTheKeyDerivedFromTheSecret(
        string algorithm, string contentEncryption, string expectedKeyHex)
    {
        var key = await Resolver().ResolveAsync(
            NoProfile, ClientHolding(new ClientSecret { Value = ClientSecret }), algorithm, contentEncryption);

        var derived = Assert.IsType<OctetJsonWebKey>(key);
        Assert.Equal(Convert.FromHexString(expectedKeyHex), derived.KeyValue);
        Assert.Equal(algorithm, derived.Algorithm);
    }

    /// <summary>
    /// The derived key is one the client holds too: a JWT this server encrypts to it opens with the key the client
    /// computes from its own secret, under key wrapping and under direct encryption.
    /// </summary>
    [Theory]
    [InlineData(KeyManagement.Aes128KW, ContentEncryption.Aes128CbcHmacSha256, "EE295520A9FF3D46618AF0828E11935E")]
    [InlineData(KeyManagement.Dir, ContentEncryption.Aes128CbcHmacSha256,
        "EE295520A9FF3D46618AF0828E11935EF581020690836B6A1F5CA2BFFEDFE95A")]
    public async Task AJwtEncryptedToTheDerivedKey_OpensWithTheClientsOwnKey(
        string algorithm, string contentEncryption, string clientKeyHex)
    {
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens();
        await using var provider = services.BuildServiceProvider();
        var creator = provider.GetRequiredService<IJsonWebTokenCreator>();

        var key = await Resolver(creator).ResolveAsync(
            NoProfile, ClientHolding(new ClientSecret { Value = ClientSecret }), algorithm, contentEncryption);

        var signingKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload = { JwtId = "jti", Issuer = "https://op.example.com", Audiences = [TestConstants.DefaultClientId] },
        };
        var jwe = await creator.IssueAsync(token, signingKey, Assert.IsType<OctetJsonWebKey>(key), algorithm, contentEncryption);

        var clientKey = new OctetJsonWebKey { KeyValue = Convert.FromHexString(clientKeyHex) };
        var opened = await provider.GetRequiredService<IJsonWebTokenValidator>().ValidateAsync(jwe, new ValidationParameters
        {
            TokenTypes = TokenTypePolicy.CheckedByCaller,
            ValidateAudience = _ => Task.FromResult(true),
            ValidateIssuer = _ => Task.FromResult(true),
            ResolveTokenDecryptionKeys = _ => clientKey.ToAsync(),
            ResolveIssuerSigningKeys = _ => signingKey.ToAsync(),
        });

        Assert.True(opened.TryGetSuccess(out var decrypted));
        Assert.Equal("jti", decrypted.Payload.JwtId);
    }

    /// <summary>
    /// Section 10.2 derives the symmetric key from the client secret only: a client whose secret is stored as its hash
    /// alone, has expired, or that is public ("Symmetric encryption MUST NOT be used by public (non-confidential)
    /// Clients") has no key, and an octet key it publishes is never used - its JWK Set "MUST NOT contain private or
    /// symmetric key values" (OpenID Connect Dynamic Client Registration 1.0 section 2).
    /// </summary>
    [Theory]
    [InlineData("hash only")]
    [InlineData("expired")]
    [InlineData("public")]
    public async Task ASymmetricAlgorithm_WithoutASecretTheServerReads_HasNoKey(string client)
    {
        var expired = Now.AddMinutes(-1);
        var clientInfo = client switch
        {
            "hash only" => ClientHolding(new ClientSecret { Sha512Hash = [1] }),
            "expired" => ClientHolding(new ClientSecret { Value = ClientSecret, ExpiresAt = expired }),
            "public" => ClientHolding(new ClientSecret { Value = ClientSecret }) with
            {
                TokenEndpointAuthMethod = ClientAuthenticationMethods.None,
            },
            _ => throw new ArgumentOutOfRangeException(nameof(client), client, null),
        };

        var key = await Resolver().ResolveAsync(
            NoProfile, clientInfo, KeyManagement.Aes128KW, ContentEncryption.Aes128CbcHmacSha256);

        Assert.Null(key);
        _clientKeys.Verify(k => k.GetEncryptionKeys(It.IsAny<ClientInfo>()), Times.Never);
    }

    /// <summary>
    /// An expired secret is passed over for the next one the client holds.
    /// </summary>
    [Fact]
    public async Task AnExpiredSecret_IsPassedOverForTheNext()
    {
        var clientInfo = ClientHolding(
            new ClientSecret { Value = "an-expired-secret", ExpiresAt = Now.AddMinutes(-1) },
            new ClientSecret { Value = ClientSecret });

        var key = await Resolver().ResolveAsync(
            NoProfile, clientInfo, KeyManagement.Aes128KW, ContentEncryption.Aes128CbcHmacSha256);

        Assert.Equal(
            Convert.FromHexString("EE295520A9FF3D46618AF0828E11935E"), Assert.IsType<OctetJsonWebKey>(key).KeyValue);
    }

    /// <summary>
    /// Of two secrets the server can read, the one expiring last is derived from, one that never expires before any
    /// other: a client rotating its secret holds the newer one.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task OfSeveralSecrets_TheOneExpiringLastIsUsed(bool newerNeverExpires)
    {
        var clientInfo = ClientHolding(
            new ClientSecret { Value = "the-older-secret", ExpiresAt = Now.AddDays(1) },
            new ClientSecret { Value = ClientSecret, ExpiresAt = newerNeverExpires ? null : Now.AddDays(30) });

        var key = await Resolver().ResolveAsync(
            NoProfile, clientInfo, KeyManagement.Aes128KW, ContentEncryption.Aes128CbcHmacSha256);

        Assert.Equal(
            Convert.FromHexString("EE295520A9FF3D46618AF0828E11935E"), Assert.IsType<OctetJsonWebKey>(key).KeyValue);
    }

    /// <summary>
    /// Section 10.2 derives a key for AES key wrapping and direct encryption alone, so a password-based algorithm has
    /// none, and neither has dir under a content encryption algorithm whose key length is not known here.
    /// </summary>
    [Theory]
    [InlineData(KeyManagement.Pbes2HmacSha256Aes128KW, ContentEncryption.Aes128CbcHmacSha256)]
    [InlineData(KeyManagement.Dir, "A512-HOST")]
    public async Task ASymmetricAlgorithmSection10_2DerivesNoKeyFor_HasNone(string algorithm, string contentEncryption)
    {
        var key = await Resolver().ResolveAsync(
            NoProfile, ClientHolding(new ClientSecret { Value = ClientSecret }), algorithm, contentEncryption);

        Assert.Null(key);
    }

    /// <summary>
    /// An asymmetric algorithm encrypts to a key the client publishes, and to none derived from its secret; an octet key
    /// in its JWK Set is not one, whatever it declares.
    /// </summary>
    [Fact]
    public async Task AnAsymmetricAlgorithm_EncryptsToAPublishedKeyOnly()
    {
        var published = new RsaJsonWebKey { KeyId = "rsa", Usage = PublicKeyUsages.Encryption };
        var clientInfo = ClientHolding(new ClientSecret { Value = ClientSecret });
        _clientKeys
            .Setup(k => k.GetEncryptionKeys(clientInfo))
            .Returns(new JsonWebKey[] { new OctetJsonWebKey { KeyValue = new byte[32] }, published }.ToAsyncEnumerable());

        var key = await Resolver().ResolveAsync(
            NoProfile, clientInfo, KeyManagement.RsaOaep256, ContentEncryption.Aes128CbcHmacSha256);

        Assert.Same(published, key);
    }

    /// <summary>
    /// A key management algorithm the host registers under its own name for RSA keys is advertised from the registry,
    /// so an RSA key the client publishes declaring it for encryption is the key a JWT is encrypted to under it.
    /// </summary>
    [Fact]
    public async Task AHostsAlgorithm_EncryptsToAPublishedKeyDeclaringIt()
    {
        var published = new RsaJsonWebKey
        {
            KeyId = "rsa", Usage = PublicKeyUsages.Encryption, Algorithm = HostRsaAlgorithm,
        };
        var clientInfo = ClientHolding(new ClientSecret { Value = ClientSecret });
        _clientKeys
            .Setup(k => k.GetEncryptionKeys(clientInfo))
            .Returns(new JsonWebKey[] { published }.ToAsyncEnumerable());
        var creator = new Mock<IJsonWebTokenCreator>(MockBehavior.Strict);
        creator.Setup(c => c.EncryptedResponseAlgorithmsSupported).Returns([HostRsaAlgorithm]);

        var key = await Resolver(creator.Object).ResolveAsync(
            NoProfile, clientInfo, HostRsaAlgorithm, ContentEncryption.Aes128CbcHmacSha256);

        Assert.Same(published, key);
    }

    /// <summary>
    /// A symmetric algorithm is not served by an octet key the client publishes, even where it holds no secret.
    /// </summary>
    [Fact]
    public async Task ASymmetricAlgorithm_IsNotServedByAPublishedOctetKey()
    {
        var clientInfo = ClientHolding();
        _clientKeys
            .Setup(k => k.GetEncryptionKeys(clientInfo))
            .Returns(new JsonWebKey[]
            {
                new OctetJsonWebKey { Algorithm = KeyManagement.Aes128KW, KeyValue = new byte[16] },
            }.ToAsyncEnumerable());

        var key = await Resolver().ResolveAsync(
            NoProfile, clientInfo, KeyManagement.Aes128KW, ContentEncryption.Aes128CbcHmacSha256);

        Assert.Null(key);
    }

    /// <summary>
    /// A derived key is held to what the host performs as a published one is: a symmetric algorithm the host does not
    /// perform has no key.
    /// </summary>
    [Fact]
    public async Task ASymmetricAlgorithmTheHostDoesNotPerform_HasNoKey()
    {
        var creator = new Mock<IJsonWebTokenCreator>(MockBehavior.Strict);
        creator.Setup(c => c.EncryptedResponseAlgorithmsSupported).Returns([KeyManagement.RsaOaep256]);

        var key = await Resolver(creator.Object).ResolveAsync(
            NoProfile,
            ClientHolding(new ClientSecret { Value = ClientSecret }),
            KeyManagement.Aes128KW,
            ContentEncryption.Aes128CbcHmacSha256);

        Assert.Null(key);
    }
}
