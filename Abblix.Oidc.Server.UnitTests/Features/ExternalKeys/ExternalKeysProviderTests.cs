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
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ExternalKeys;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ExternalKeys;

/// <summary>
/// Verifies that <see cref="ExternalKeysProvider"/> publishes every version of a custodian key public-only,
/// stamps the configured use and algorithm while keeping each version's kid, and orders the set produce-first:
/// the active version (newest past the server's key-rollover propagation window) leads, a freshly rotated version
/// trails as announced-but-not-yet-signing, and a single non-rotating key is served as-is.
/// </summary>
public class ExternalKeysProviderTests
{
    [Fact]
    public async Task GetSigningKeys_StampsConfiguredAlgorithm_OnAnRsaKey()
    {
        using var rsa = RSA.Create(2048);
        var custodian = CustodianWith("sign-key", BareVersion(new RsaJsonWebKey().Apply(rsa.ExportParameters(false))));
        var provider = Provider(custodian, TimeProvider.System, TimeSpan.FromHours(1),
            signingKeyName: "sign-key", signingAlgorithm: SigningAlgorithms.PS256);

        var key = await SingleAsync(provider.GetSigningKeys(), TestContext.Current.CancellationToken);

        Assert.IsType<RsaJsonWebKey>(key);
        Assert.Equal("sign-key", key.KeyId);
        Assert.Equal(PublicKeyUsages.Signature, key.Usage);
        Assert.Equal(SigningAlgorithms.PS256, key.Algorithm);
        Assert.True(key.HasPublicKey);
        Assert.False(key.HasPrivateKey);
    }

    [Fact]
    public async Task GetSigningKeys_StampsConfiguredAlgorithm_OnAnEcKey()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var custodian = CustodianWith(
            "sign-key", BareVersion(new EllipticCurveJsonWebKey().Apply(ecdsa.ExportParameters(false))));
        var provider = Provider(custodian, TimeProvider.System, TimeSpan.FromHours(1),
            signingKeyName: "sign-key", signingAlgorithm: SigningAlgorithms.ES256);

        var key = await SingleAsync(provider.GetSigningKeys(), TestContext.Current.CancellationToken);

        // The provider keeps the custodian's key type; an EC key is published as an EC JWK.
        Assert.IsType<EllipticCurveJsonWebKey>(key);
        Assert.Equal("sign-key", key.KeyId);
        Assert.Equal(PublicKeyUsages.Signature, key.Usage);
        Assert.Equal(SigningAlgorithms.ES256, key.Algorithm);
        Assert.False(key.HasPrivateKey);
    }

    [Fact]
    public async Task GetEncryptionKeys_StampsConfiguredAlgorithm()
    {
        using var rsa = RSA.Create(2048);
        var custodian = CustodianWith("enc-key", BareVersion(new RsaJsonWebKey().Apply(rsa.ExportParameters(false))));
        var provider = Provider(custodian, TimeProvider.System, TimeSpan.FromHours(1),
            encryptionKeyName: "enc-key", encryptionAlgorithm: EncryptionAlgorithms.KeyManagement.RsaOaep);

        var key = await SingleAsync(provider.GetEncryptionKeys(), TestContext.Current.CancellationToken);

        Assert.Equal("enc-key", key.KeyId);
        Assert.Equal(PublicKeyUsages.Encryption, key.Usage);
        Assert.Equal(EncryptionAlgorithms.KeyManagement.RsaOaep, key.Algorithm);
        Assert.False(key.HasPrivateKey);
    }

    [Fact]
    public async Task GetEncryptionKeys_PublishesNothing_WhenNoEncryptionKeyIsNamed()
    {
        var custodian = new Mock<IKeyCustodian>(MockBehavior.Strict);
        var provider = Provider(custodian.Object, TimeProvider.System, TimeSpan.FromHours(1),
            encryptionKeyName: null);

        var keys = await ToListAsync(provider.GetEncryptionKeys(), TestContext.Current.CancellationToken);

        // A signing-only deployment holds no encryption key, so a guessed name would fail against the custodian.
        // The strict mock proves the provider does not ask for one.
        Assert.Empty(keys);
    }

    [Fact]
    public async Task GetSigningKeys_PublishesEveryVersion_KeepingEachVersionsKid()
    {
        var now = new DateTimeOffset(2026, 7, 16, 12, 0, 0, TimeSpan.Zero);
        var custodian = CustodianWith(
            "sign-key",
            VersionAt("v1", now - TimeSpan.FromDays(2)),
            VersionAt("v2", now - TimeSpan.FromHours(1)));
        var provider = Provider(custodian, TimeAt(now), TimeSpan.FromMinutes(30), signingKeyName: "sign-key");

        var keys = await ToListAsync(provider.GetSigningKeys(), TestContext.Current.CancellationToken);

        // Both versions are published, each carrying the custodian-assigned kid (not the configured key name).
        Assert.Equal(new[] { "v1", "v2" }, keys.Select(k => k.KeyId).OrderBy(k => k));
        Assert.All(keys, k => Assert.False(k.HasPrivateKey));
    }

    [Fact]
    public async Task GetSigningKeys_ActiveIsNewestPastPropagation_FreshVersionTrailsAsPending()
    {
        var now = new DateTimeOffset(2026, 7, 16, 12, 0, 0, TimeSpan.Zero);
        var propagation = TimeSpan.FromMinutes(30);

        var old = VersionAt("v1", now - TimeSpan.FromDays(2));       // long past propagation
        var active = VersionAt("v2", now - TimeSpan.FromHours(1));   // past propagation, newest such
        var fresh = VersionAt("v3", now - TimeSpan.FromMinutes(5));  // within the 30-minute window, still pending

        // Custodian enumeration order is irrelevant; the provider imposes the produce-first order.
        var custodian = CustodianWith("sign-key", fresh, active, old);
        var provider = Provider(custodian, TimeAt(now), propagation, signingKeyName: "sign-key");

        var keys = await ToListAsync(provider.GetSigningKeys(), TestContext.Current.CancellationToken);

        Assert.Equal(3, keys.Count); // every version is published for verification and rotation overlap
        Assert.Equal("v2", keys[0].KeyId); // the produce role signs with the newest version PAST propagation
        Assert.Contains(keys, k => k.KeyId == "v3"); // the still-propagating version is announced, never leads
    }

    [Fact]
    public async Task GetSigningKeys_AllVersionsWithinPropagation_NewestLeads_Bootstrap()
    {
        var now = new DateTimeOffset(2026, 7, 16, 12, 0, 0, TimeSpan.Zero);
        var propagation = TimeSpan.FromHours(1);

        var newer = VersionAt("v1", now - TimeSpan.FromMinutes(20));
        var newest = VersionAt("v2", now - TimeSpan.FromMinutes(2));

        // Both are still inside the window; with no version past propagation the newest overall must lead, so the
        // very first rollover still has something to sign with. There is no older version a client could hold.
        var custodian = CustodianWith("sign-key", newer, newest);
        var provider = Provider(custodian, TimeAt(now), propagation, signingKeyName: "sign-key");

        var keys = await ToListAsync(provider.GetSigningKeys(), TestContext.Current.CancellationToken);

        Assert.Equal(2, keys.Count);
        Assert.Equal("v2", keys[0].KeyId);
    }

    private static ExternalKeysProvider Provider(
        IKeyCustodian custodian,
        TimeProvider timeProvider,
        TimeSpan propagation,
        string signingKeyName = "sign-key",
        string signingAlgorithm = SigningAlgorithms.RS256,
        string? encryptionKeyName = "enc-key",
        string encryptionAlgorithm = EncryptionAlgorithms.KeyManagement.RsaOaep256)
    {
        var keys = new CustodianHeldKeys
        {
            SigningKeyName = signingKeyName,
            SigningAlgorithm = signingAlgorithm,
            EncryptionKeyName = encryptionKeyName,
            EncryptionAlgorithm = encryptionAlgorithm,
        };
        var options = Options.Create(new OidcOptions { KeyRolloverPropagation = propagation });
        return new ExternalKeysProvider(custodian, keys, options, timeProvider);
    }

    private static IKeyCustodian CustodianWith(string keyName, params KeyVersion[] versions)
    {
        var custodian = new Mock<IKeyCustodian>();
        custodian.Setup(c => c.GetKeyVersionsAsync(keyName, It.IsAny<CancellationToken>()))
            .Returns(versions.ToAsyncEnumerable());
        return custodian.Object;
    }

    // A version with an unset creation time and no kid, standing for a single non-rotating custodian key.
    private static KeyVersion BareVersion(JsonWebKey publicKey) => new(publicKey, DateTimeOffset.MinValue);

    // A version carrying the custodian-assigned kid and a creation time, for the produce-first ordering tests.
    private static KeyVersion VersionAt(string kid, DateTimeOffset createdAt)
    {
        using var rsa = RSA.Create(2048);
        var publicKey = new RsaJsonWebKey().Apply(rsa.ExportParameters(false)) with { KeyId = kid };
        return new KeyVersion(publicKey, createdAt);
    }

    private static async Task<JsonWebKey> SingleAsync(IAsyncEnumerable<JsonWebKey> keys, CancellationToken ct)
        => Assert.Single(await ToListAsync(keys, ct));

    private static async Task<List<JsonWebKey>> ToListAsync(IAsyncEnumerable<JsonWebKey> keys, CancellationToken ct)
    {
        var list = new List<JsonWebKey>();
        await foreach (var key in keys.WithCancellation(ct))
            list.Add(key);
        return list;
    }

    private static TimeProvider TimeAt(DateTimeOffset now)
    {
        var timeProvider = new Mock<TimeProvider>();
        timeProvider.Setup(t => t.GetUtcNow()).Returns(now);
        return timeProvider.Object;
    }
}
