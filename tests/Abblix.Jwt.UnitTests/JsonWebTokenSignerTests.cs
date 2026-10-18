// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Buffers.Text;
using System.Text.Json.Nodes;
using Abblix.Jwt.ExternalKeys;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// The refusals of the JWS signer that nothing else in this suite holds: what it does with a header that
/// contradicts the key, with no key at all, and with a signature or a key it cannot verify under.
/// </summary>
public class JsonWebTokenSignerTests
{
    private static readonly JsonWebKey SigningKey =
        JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);

    private static IJsonWebTokenSigner Signer(IKeyCustodian? custodian = null)
    {
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens();
        if (custodian != null)
        {
            services.AddSingleton(custodian);
            services.ComposeExternalKeyBackends();
        }

        return services.BuildServiceProvider().GetRequiredService<IJsonWebTokenSigner>();
    }

    private static JsonWebToken NewToken() => new()
    {
        Header = { Type = "JWT" },
        Payload = { Subject = "user-1" },
    };

    /// <summary>
    /// A signature that is not valid base64url makes the token malformed, which a caller answers differently from a
    /// signature that does not match.
    /// </summary>
    [Fact]
    public async Task ASignatureThatIsNotBase64Url_IsAMalformedToken()
    {
        var header = new JsonWebTokenHeader(new JsonObject { ["alg"] = SigningAlgorithms.RS256 });

        var error = await Signer().ValidateAsync(
            ["e30", "e30", "not base64url!"], header, new[] { SigningKey.Sanitize(false) }.ToAsyncEnumerable(),
            TestContext.Current.CancellationToken);

        Assert.NotNull(error);
        Assert.Equal(JwtError.MalformedToken, error.Error);
    }

    /// <summary>
    /// Without a key the token is issued unsigned, and a key identifier would name a key nothing signed with.
    /// </summary>
    [Fact]
    public async Task AnUnsignedToken_CarriesNoKeyId()
    {
        var token = NewToken();
        token.Header.KeyId = "some-key";

        var jwt = await Signer().SignAsync(token, null, TestContext.Current.CancellationToken);

        var header = JsonNode.Parse(Base64Url.DecodeFromChars(jwt.Split('.')[0]))!.AsObject();
        Assert.Equal(SigningAlgorithms.None, header["alg"]!.GetValue<string>());
        Assert.False(header.ContainsKey("kid"));
    }

    /// <summary>
    /// A header asking for an unsigned token contradicts the key it is handed, so nothing is issued. The key's private
    /// half is held by a custodian that signs whatever it is asked to, as a host's own may: nothing after the signer
    /// would refuse, and the token would go out marked unsigned while carrying a signature.
    /// </summary>
    [Fact]
    public async Task AHeaderNamingNone_WithAKey_IsRefused()
    {
        var token = NewToken();
        token.Header.Algorithm = SigningAlgorithms.None;

        // A key declaring no algorithm, so the refusal is the unsigned header's and not a mismatch with the key
        var publicOnlyKey = SigningKey.Sanitize(includePrivateKeys: false) with { Algorithm = null };
        var custodian = new CountingCustodian();

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => Signer(custodian).SignAsync(token, publicOnlyKey, TestContext.Current.CancellationToken));
        Assert.Equal(0, custodian.SignCalls);
    }

    /// <summary>A header naming another algorithm than the key declares is refused rather than signed under either.</summary>
    [Fact]
    public async Task AHeaderAndAKeyNamingDifferentAlgorithms_IsRefused()
    {
        var token = NewToken();
        token.Header.Algorithm = SigningAlgorithms.RS384;

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => Signer().SignAsync(token, SigningKey, TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A key with no public half cannot verify anything, which is a fault in the keys the caller resolved rather than
    /// a property of the token.
    /// </summary>
    [Fact]
    public async Task AKeyWithoutItsPublicHalf_IsAFault()
    {
        var header = new JsonWebTokenHeader(new JsonObject { ["alg"] = SigningAlgorithms.RS256 });
        var keyWithoutPublicHalf = new RsaJsonWebKey { Algorithm = SigningAlgorithms.RS256 };

        await Assert.ThrowsAsync<InvalidOperationException>(() => Signer().ValidateAsync(
            ["e30", "e30", "AQAB"], header, new JsonWebKey[] { keyWithoutPublicHalf }.ToAsyncEnumerable(),
            TestContext.Current.CancellationToken));
    }

    /// <summary>Signs under whatever algorithm it is asked for, checking nothing, and counts the requests.</summary>
    private sealed class CountingCustodian : IKeyCustodian
    {
        public int SignCalls { get; private set; }

        public Task<byte[]> SignAsync(string keyId, string algorithm, byte[] data, CancellationToken cancellationToken)
        {
            SignCalls++;
            return Task.FromResult<byte[]>([1]);
        }

        public Task<byte[]?> UnwrapKeyAsync(
            string keyId,
            string algorithm,
            JsonWebTokenHeader header,
            byte[] encryptedKey,
            CancellationToken cancellationToken)
            => Task.FromResult<byte[]?>(null);

        public Task<byte[]?> AgreeKeyAsync(
            string keyId,
            string algorithm,
            JsonWebKey ephemeralPublicKey,
            CancellationToken cancellationToken)
            => Task.FromResult<byte[]?>(null);

        public IAsyncEnumerable<KeyVersion> GetKeyVersionsAsync(string keyName, CancellationToken cancellationToken)
            => AsyncEnumerable.Empty<KeyVersion>();
    }
}
