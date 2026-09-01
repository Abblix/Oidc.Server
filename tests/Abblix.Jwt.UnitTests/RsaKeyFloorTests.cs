// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Jwt.Encryption;
using Abblix.Jwt.Signing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// The 2048-bit floor and the citation that explains it, at the sites where nothing else measures them.
/// </summary>
/// <remarks>
/// Every test here was written because a mutation survived the suite: the section a refusal cites could
/// be swapped between families, the whole encryption-side floor could be deleted, and a modulus of all
/// zero octets could be measured any way at all, each with nothing going red. No pass count is given,
/// because it was a mid-branch one and a figure that no longer reproduces reads as evidence.
/// </remarks>
public class RsaKeyFloorTests
{
    /// <summary>
    /// RFC 7518 states the floor four times, once per family, and never in the container headings 3
    /// and 4. An operator sent to a heading finds a table of algorithm names and no MUST, which reads
    /// as the library having invented the rule.
    /// </summary>
    [Theory]
    [InlineData(SigningAlgorithms.RS256, "Section 3.3")]
    [InlineData(SigningAlgorithms.RS384, "Section 3.3")]
    [InlineData(SigningAlgorithms.RS512, "Section 3.3")]
    [InlineData(SigningAlgorithms.PS256, "Section 3.5")]
    [InlineData(SigningAlgorithms.PS384, "Section 3.5")]
    [InlineData(SigningAlgorithms.PS512, "Section 3.5")]
    [InlineData(EncryptionAlgorithms.KeyManagement.Rsa1_5, "Section 4.2")]
    [InlineData(EncryptionAlgorithms.KeyManagement.RsaOaep, "Section 4.3")]
    [InlineData(EncryptionAlgorithms.KeyManagement.RsaOaep256, "Section 4.3")]
    public void RsaSectionFor_NamesTheSectionThatCarriesTheRequirement(string algorithm, string expected)
        => Assert.Equal(expected, JsonWebKeyExtensions.RsaSectionFor(algorithm));

    [Fact]
    public void RsaSectionFor_AnAlgorithmWithNoFloor_Refuses()
        => Assert.Throws<ArgumentException>(
            () => JsonWebKeyExtensions.RsaSectionFor(SigningAlgorithms.ES256));

    /// <summary>
    /// The message-building form must never throw, because it is called while composing a refusal: an
    /// unknown algorithm there would replace the size refusal the operator was about to read.
    /// </summary>
    [Theory]
    [InlineData(SigningAlgorithms.RS256, "per RFC 7518 Section 3.3")]
    [InlineData(SigningAlgorithms.PS512, "per RFC 7518 Section 3.5")]
    [InlineData(SigningAlgorithms.None, "for RSA signatures")]
    [InlineData(SigningAlgorithms.ES256, "for RSA signatures")]
    public void RsaSectionForOrNothing_NeverThrows(string algorithm, string expected)
        => Assert.Equal(expected, JsonWebKeyExtensions.RsaSectionForOrNothing(algorithm));

    /// <summary>
    /// The encryption-side floor. Deleting it outright used to pass the whole suite.
    /// </summary>
    [Fact]
    public void EncryptKey_AKeyBelowTheFloor_IsRefused()
    {
        var encryptor = new RsaKeyEncryptor(
            NullLogger<RsaKeyEncryptor>.Instance, EncryptionAlgorithms.KeyManagement.RsaOaep256);

        var error = Assert.Throws<InvalidOperationException>(
            () => encryptor.EncryptKey(HeaderFor(EncryptionAlgorithms.KeyManagement.RsaOaep256),
                PublicOnlyKey(1024), new byte[32]));

        Assert.Contains("1024", error.Message);
        Assert.Contains(JsonWebKeyExtensions.MinimumRsaKeyBits.ToString(), error.Message);

        // The half a swapped citation would break: RSA-OAEP-256 is governed by Section 4.3, and an
        // operator who opens Section 4 instead finds nothing that refuses anything.
        Assert.Contains("Section 4.3", error.Message);
    }

    /// <summary>
    /// The control. Without it an encryptor that refused every key would pass the test above.
    /// </summary>
    [Fact]
    public void EncryptKey_AKeyAtTheFloor_Encrypts()
    {
        var encryptor = new RsaKeyEncryptor(
            NullLogger<RsaKeyEncryptor>.Instance, EncryptionAlgorithms.KeyManagement.RsaOaep256);

        var encrypted = encryptor.EncryptKey(
            HeaderFor(EncryptionAlgorithms.KeyManagement.RsaOaep256),
            PublicOnlyKey(JsonWebKeyExtensions.MinimumRsaKeyBits),
            new byte[32]);

        Assert.Equal(JsonWebKeyExtensions.MinimumRsaKeyBits / 8, encrypted.Length);
    }

    /// <summary>
    /// A modulus carrying no value at all measures zero, so it fails the floor rather than sliding
    /// past a check written as "not obviously too small".
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData(new byte[0])]
    [InlineData(new byte[] { 0 })]
    [InlineData(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 })]
    public void ModulusBitLength_NothingToMeasure_IsZero(byte[]? modulus)
        => Assert.Equal(0, new RsaJsonWebKey { Modulus = modulus }.ModulusBitLength());

    /// <summary>
    /// The leading octet contributes only from its own highest set bit, so a modulus that happens to
    /// begin below 0x80 measures shorter than its octet count - which is its true length.
    /// </summary>
    [Theory]
    [InlineData(new byte[] { 0x01 }, 1)]
    [InlineData(new byte[] { 0x80 }, 8)]
    [InlineData(new byte[] { 0xFF }, 8)]
    [InlineData(new byte[] { 0x00, 0x80 }, 8)]
    [InlineData(new byte[] { 0x01, 0x00 }, 9)]
    public void ModulusBitLength_MeasuresFromTheHighestSetBit(byte[] modulus, int expected)
        => Assert.Equal(expected, new RsaJsonWebKey { Modulus = modulus }.ModulusBitLength());

    /// <summary>
    /// Minting is where a configured key size becomes a key, so it is where a size this library will
    /// later refuse to sign with has to be refused.
    /// </summary>
    /// <remarks>
    /// How early that lands still depends on the ring. <c>KeyRing</c> mints on its first refresh, inside
    /// the hosted service, so the process stops at startup. <c>InMemoryKeyRing</c> mints lazily by
    /// design, so a misconfigured host reaches this refusal on its first JWKS or token request instead.
    /// Closing that difference means validating the configured size at startup, which is its own change.
    /// </remarks>
    [Fact]
    public void CreateRsa_BelowTheFloor_Refuses()
    {
        var error = Assert.Throws<ArgumentException>(
            () => JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256, 1024));

        Assert.Contains("1024", error.Message);
        Assert.Contains(JsonWebKeyExtensions.MinimumRsaKeyBits.ToString(), error.Message);
    }

    [Fact]
    public void CreateRsa_AtTheFloor_Mints()
    {
        var key = JsonWebKeyFactory.CreateRsa(
            PublicKeyUsages.Signature, SigningAlgorithms.RS256, JsonWebKeyExtensions.MinimumRsaKeyBits);

        Assert.Equal(JsonWebKeyExtensions.MinimumRsaKeyBits, key.ModulusBitLength());
    }

    private static JsonWebTokenHeader HeaderFor(string algorithm)
        => new(new JsonObject())
        {
            Algorithm = algorithm,
            EncryptionAlgorithm = EncryptionAlgorithms.ContentEncryption.Aes256Gcm,
        };

    /// <summary>
    /// A verification that failed because a candidate key is under the floor SAYS so, naming the key and
    /// both sizes.
    /// </summary>
    /// <remarks>
    /// The refusal itself is right and stays as it is: an undersized key from a peer is a signature that
    /// does not check out, and <c>Verify</c> returning false is what says that. What was wrong was the
    /// silence around it. The case is not a hostile peer but a rotation - a key ring holding one retired
    /// sub-floor key signs new tokens with the leading key and fails every token signed before the
    /// upgrade, all of them labelled as tampering, with nothing anywhere naming a size.
    /// <para>
    /// Driven through the real signer rather than through the reporting method, because the property is
    /// that the two arrive together: a test calling the reporter directly would pass over a build where
    /// nothing calls it.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task ValidateAsync_ACandidateKeyBelowTheFloor_IsNamedInTheLog()
    {
        var log = new CapturingLogger();
        var (token, key) = SignedWithAnRsaKeyOf(1024);

        var error = await SignerWith(log).ValidateAsync(
            token.Split('.'), HeaderOf(token), Keys(key), TestContext.Current.CancellationToken);

        Assert.Equal(JwtError.InvalidSignature, Assert.IsType<JwtValidationError>(error).Error);

        var warning = Assert.Single(log.Entries);
        Assert.Equal(LogLevel.Warning, warning.Level);
        Assert.Contains("1024", warning.Message);
        Assert.Contains(JsonWebKeyExtensions.MinimumRsaKeyBits.ToString(), warning.Message);
        Assert.Contains(key.KeyId!, warning.Message);
    }

    /// <summary>
    /// The control. Without it a reporter that named every failed verification as undersized would pass
    /// the row above, and every ordinary bad signature would arrive carrying a key-size explanation.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ASignatureThatSimplyDoesNotMatch_SaysNothingAboutSizes()
    {
        var log = new CapturingLogger();
        var (token, _) = SignedWithAnRsaKeyOf(JsonWebKeyExtensions.MinimumRsaKeyBits);
        var (_, somebodyElse) = SignedWithAnRsaKeyOf(JsonWebKeyExtensions.MinimumRsaKeyBits);

        var error = await SignerWith(log).ValidateAsync(
            token.Split('.'), HeaderOf(token), Keys(somebodyElse), TestContext.Current.CancellationToken);

        Assert.Equal(JwtError.InvalidSignature, Assert.IsType<JwtValidationError>(error).Error);
        Assert.Empty(log.Entries);
    }

    /// <summary>The header the validator is handed, read back from the token itself.</summary>
    private static JsonWebTokenHeader HeaderOf(string token)
        => new(JsonNode.Parse(Base64Url.DecodeFromChars(token.Split('.')[0]))!.AsObject());

    /// <summary>
    /// A signed JWS and the public half of the key that signed it, at whatever size is asked for.
    /// </summary>
    /// <remarks>
    /// Signed through <see cref="RSA"/> directly rather than through this library's signer, which refuses
    /// an undersized key on the signing side - correctly, and it is the token minted BEFORE such a key
    /// was retired that this is about.
    /// </remarks>
    private static (string Token, RsaJsonWebKey Key) SignedWithAnRsaKeyOf(int bits)
    {
        using var rsa = RSA.Create(bits);
        var parameters = rsa.ExportParameters(false);
        var key = new RsaJsonWebKey
        {
            KeyId = $"retired-{bits}",
            Usage = PublicKeyUsages.Signature,
            Algorithm = SigningAlgorithms.RS256,
            Modulus = parameters.Modulus,
            Exponent = parameters.Exponent,
        };

        var header = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(
            $$"""{"alg":"RS256","typ":"JWT","kid":"{{key.KeyId}}"}"""));
        var payload = Base64Url.EncodeToString(Encoding.UTF8.GetBytes("""{"sub":"someone"}"""));
        var signature = rsa.SignData(
            Encoding.UTF8.GetBytes($"{header}.{payload}"), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return ($"{header}.{payload}.{Base64Url.EncodeToString(signature)}", key);
    }

    private static async IAsyncEnumerable<JsonWebKey> Keys(params JsonWebKey[] keys)
    {
        foreach (var key in keys)
        {
            yield return key;
        }

        await Task.CompletedTask;
    }

    private static JsonWebTokenSigner SignerWith(CapturingLogger log)
    {
        var services = new ServiceCollection();
        services.AddKeyedSingleton<ISignatureAlgorithm<RsaJsonWebKey>>(
            SigningAlgorithms.RS256, (_, _) => new RsaSigner(SigningAlgorithms.RS256));

        return new JsonWebTokenSigner(log, services.BuildServiceProvider(), NoSigning.Instance);
    }

    /// <summary>The signing seam, which the verify path never reaches.</summary>
    private sealed class NoSigning : IDataSigner
    {
        public static readonly NoSigning Instance = new();

        public bool CanSign(JsonWebKey key) => false;

        public Task<byte[]> SignAsync(
            JsonWebKey key, string algorithm, byte[] data, CancellationToken cancellationToken)
            => throw new NotSupportedException("The verify path does not sign.");
    }

    private sealed class CapturingLogger : ILogger<JsonWebTokenSigner>
    {
        private readonly List<(LogLevel Level, string Message)> _entries = [];

        public IReadOnlyList<(LogLevel Level, string Message)> Entries => _entries;

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
            => _entries.Add((logLevel, formatter(state, exception)));
    }


    /// <summary>
    /// The report is silent about a key whose ALGORITHM has no size requirement, however small the key is.
    /// </summary>
    /// <remarks>
    /// RFC 7518 states the 2048 four times, once per family, and Section 3.4 - ECDSA - states none at
    /// all. An RSA key stays a candidate for an algorithm it does not contradict, because a key that
    /// declares no <c>alg</c> is deliberately not filtered out, so an ungated report speaks for every
    /// failed verification an RSA key was near.
    /// <para>
    /// The HS256 row is why this is a defect rather than an inaccuracy: taking an issuer's RSA public key
    /// and signing with an HMAC algorithm is the textbook algorithm-confusion probe, and the message this
    /// would attach to that burst told the operator it was a retired key rather than an attack.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(SigningAlgorithms.ES256)]
    [InlineData(SigningAlgorithms.HS256)]
    public async Task ValidateAsync_AnAlgorithmWithNoRsaFloor_SaysNothingAboutSizes(string algorithm)
    {
        var log = new CapturingLogger();
        var (token, key) = SignedWithAnRsaKeyOf(1024);
        key.Algorithm = null;

        var header = new JsonWebTokenHeader(new JsonObject
        {
            { "alg", algorithm },
            { "typ", "JWT" },
        });

        await SignerWith(log).ValidateAsync(
            token.Split('.'), header, Keys(key), TestContext.Current.CancellationToken);

        Assert.Empty(log.Entries);
    }

    /// <summary>
    /// An undersized HMAC secret is named, which is the half the shared floor was extracted for.
    /// </summary>
    /// <remarks>
    /// Moving the HMAC minimum out of <c>HmacSigner</c> so the signer and the report read one source is
    /// the point of that extraction, and nothing measured the report's side of it: an arm that could
    /// never fire left the whole suite green.
    /// </remarks>
    [Fact]
    public async Task ValidateAsync_AnUndersizedHmacSecret_IsNamedInTheLog()
    {
        var log = new CapturingLogger();
        var key = new OctetJsonWebKey
        {
            KeyId = "shared-short",
            Usage = PublicKeyUsages.Signature,
            Algorithm = SigningAlgorithms.HS256,
            KeyValue = new byte[16],
        };

        var header = new JsonWebTokenHeader(new JsonObject
        {
            { "alg", SigningAlgorithms.HS256 },
            { "kid", key.KeyId },
        });

        await SignerWith(log).ValidateAsync(
            ["e30", "e30", "AAAA"], header, Keys(key), TestContext.Current.CancellationToken);

        var warning = Assert.Single(log.Entries);
        Assert.Contains("128", warning.Message, StringComparison.Ordinal);
        Assert.Contains("256", warning.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The algorithms the report gates on are the algorithms the refusal cites a section for - the same
    /// nine, kept together rather than by hand.
    /// </summary>
    /// <remarks>
    /// Two copies of one list, and nothing made them agree: narrowing the report's list to RS256 alone
    /// left the whole suite green, so a peer minting PS256 with a retired 1024-bit key would be refused
    /// by the signer and reported by nothing - the exact silence the report exists to end, restored for
    /// five of the six RSA signing algorithms.
    /// <para>
    /// Written as an agreement between the two rather than as a list of nine, because a row enumerating
    /// them is a third copy.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(SigningAlgorithms.RS256)]
    [InlineData(SigningAlgorithms.RS384)]
    [InlineData(SigningAlgorithms.RS512)]
    [InlineData(SigningAlgorithms.PS256)]
    [InlineData(SigningAlgorithms.PS384)]
    [InlineData(SigningAlgorithms.PS512)]
    [InlineData(EncryptionAlgorithms.KeyManagement.Rsa1_5)]
    [InlineData(EncryptionAlgorithms.KeyManagement.RsaOaep)]
    [InlineData(EncryptionAlgorithms.KeyManagement.RsaOaep256)]
    [InlineData(SigningAlgorithms.ES256)]
    [InlineData(SigningAlgorithms.HS256)]
    [InlineData(SigningAlgorithms.None)]
    public void MinimumRsaKeyBitsFor_AgreesWithTheSectionTheRefusalCites(string algorithm)
    {
        var hasSection = JsonWebKeyExtensions.RsaSectionForOrNothing(algorithm).StartsWith(
            "per RFC 7518", StringComparison.Ordinal);

        Assert.Equal(hasSection, JsonWebKeyExtensions.MinimumRsaKeyBitsFor(algorithm).HasValue);
    }

    private static RsaJsonWebKey PublicOnlyKey(int bits)
    {
        using var rsa = RSA.Create(bits);
        var parameters = rsa.ExportParameters(false);

        return new RsaJsonWebKey
        {
            KeyId = "floor-test",
            Usage = PublicKeyUsages.Encryption,
            Modulus = parameters.Modulus,
            Exponent = parameters.Exponent,
        };
    }
}
