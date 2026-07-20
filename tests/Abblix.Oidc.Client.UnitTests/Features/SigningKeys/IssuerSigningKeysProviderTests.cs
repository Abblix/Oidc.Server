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

using System.Net;
using Abblix.Oidc.Client.Features.Discovery;
using Abblix.Oidc.Client.Features.SigningKeys;
using Abblix.Oidc.Client.UnitTests.Features.Discovery;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Abblix.Oidc.Client.UnitTests.Features.SigningKeys;

/// <summary>
/// Tests for <see cref="IssuerSigningKeysProvider"/>.
/// </summary>
public class IssuerSigningKeysProviderTests
{
    private const string KeySetUri = "https://provider.example.com/jwks";

    /// <summary>
    /// An RSA public key in JWK form, differing only by key id so a test can tell two keys apart.
    /// </summary>
    private static string RsaKey(string keyId, string? usage = "sig") =>
        $$"""
          {
            "kty": "RSA",
            "kid": "{{keyId}}",
            {{(usage is null ? string.Empty : $"\"use\": \"{usage}\",")}}
            "alg": "RS256",
            "n": "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
            "e": "AQAB"
          }
          """;

    private static string KeySetJson(params string[] keys) => $$"""{ "keys": [{{string.Join(",", keys)}}] }""";

    private static IssuerSigningKeysProvider CreateProvider(
        StubHttpMessageHandler handler,
        TimeProvider timeProvider,
        TimeSpan? minimumRefreshInterval = null,
        string? keySetUri = KeySetUri)
    {
        var metadata = new ProviderMetadata
        {
            Issuer = "https://provider.example.com",
            JsonWebKeySetUri = keySetUri,
        };

        var options = new SigningKeysOptions();
        if (minimumRefreshInterval is { } interval)
            options.MinimumRefreshInterval = interval;

        return new IssuerSigningKeysProvider(
            new ConfiguredMetadataProvider(metadata),
            new StubHttpClientFactory(handler),
            timeProvider,
            Options.Create(options));
    }

    /// <summary>
    /// The key set is read from the address the provider's metadata names.
    /// </summary>
    [Fact]
    public async Task ReadsTheKeySetFromTheAddressTheMetadataNames()
    {
        var handler = new StubHttpMessageHandler(KeySetJson(RsaKey("key-one")));

        var keys = await CreateProvider(handler, new FakeTimeProvider())
            .GetSigningKeysAsync(null, TestContext.Current.CancellationToken);

        Assert.Equal(new Uri(KeySetUri), Assert.Single(handler.RequestedAddresses));
        Assert.Equal("key-one", Assert.Single(keys).KeyId);
    }

    /// <summary>
    /// A named key is returned alone, so verification does not try keys the token did not name.
    /// </summary>
    [Fact]
    public async Task ReturnsOnlyTheNamedKey()
    {
        var handler = new StubHttpMessageHandler(KeySetJson(RsaKey("key-one"), RsaKey("key-two")));

        var keys = await CreateProvider(handler, new FakeTimeProvider())
            .GetSigningKeysAsync("key-two", TestContext.Current.CancellationToken);

        Assert.Equal("key-two", Assert.Single(keys).KeyId);
    }

    /// <summary>
    /// A token naming a key the client has not seen makes it read the set again: that is what a rotation
    /// looks like from the client side, and rejecting it would log everyone out whenever the provider rotates.
    /// </summary>
    [Fact]
    public async Task ReReadsTheKeySetWhenTheTokenNamesAnUnknownKey()
    {
        var handler = new StubHttpMessageHandler(KeySetJson(RsaKey("old-key")));
        var provider = CreateProvider(handler, new FakeTimeProvider());

        await provider.GetSigningKeysAsync("old-key", TestContext.Current.CancellationToken);
        handler.RespondWith(KeySetJson(RsaKey("old-key"), RsaKey("rotated-key")), HttpStatusCode.OK);

        var keys = await provider.GetSigningKeysAsync("rotated-key", TestContext.Current.CancellationToken);

        Assert.Equal(2, handler.RequestedAddresses.Count);
        Assert.Equal("rotated-key", Assert.Single(keys).KeyId);
    }

    /// <summary>
    /// The re-read has a floor. The path is driven by whoever presents a token, so without one a stream of
    /// tokens naming random keys would turn this client into a load generator against its own provider.
    /// </summary>
    [Fact]
    public async Task DoesNotReReadMoreOftenThanTheFloorAllows()
    {
        var handler = new StubHttpMessageHandler(KeySetJson(RsaKey("known-key")));
        var provider = CreateProvider(handler, new FakeTimeProvider(), TimeSpan.FromMinutes(5));

        await provider.GetSigningKeysAsync("known-key", TestContext.Current.CancellationToken);

        for (var attempt = 0; attempt < 5; attempt++)
            await provider.GetSigningKeysAsync($"unknown-{attempt}", TestContext.Current.CancellationToken);

        // One read for the first call, one for the first unknown key, and none for the four that followed.
        Assert.Equal(2, handler.RequestedAddresses.Count);
    }

    /// <summary>
    /// Once the floor has passed, an unknown key is allowed to trigger a read again, so a rotation that
    /// happens after a burst of bad tokens is still picked up.
    /// </summary>
    [Fact]
    public async Task ReReadsAgainOnceTheFloorHasPassed()
    {
        var handler = new StubHttpMessageHandler(KeySetJson(RsaKey("known-key")));
        var timeProvider = new FakeTimeProvider();
        var provider = CreateProvider(handler, timeProvider, TimeSpan.FromMinutes(5));

        await provider.GetSigningKeysAsync("known-key", TestContext.Current.CancellationToken);
        await provider.GetSigningKeysAsync("unknown-key", TestContext.Current.CancellationToken);
        timeProvider.Advance(TimeSpan.FromMinutes(6));
        await provider.GetSigningKeysAsync("unknown-key", TestContext.Current.CancellationToken);

        Assert.Equal(3, handler.RequestedAddresses.Count);
    }

    /// <summary>
    /// A key still unknown after the re-read leaves every held key on the table rather than deciding the
    /// token is unverifiable: signature verification makes that call, not key selection.
    /// </summary>
    [Fact]
    public async Task FallsBackToEveryHeldKeyWhenTheNamedOneNeverAppears()
    {
        var handler = new StubHttpMessageHandler(KeySetJson(RsaKey("key-one"), RsaKey("key-two")));

        var keys = await CreateProvider(handler, new FakeTimeProvider())
            .GetSigningKeysAsync("never-published", TestContext.Current.CancellationToken);

        Assert.Equal(2, keys.Count);
    }

    /// <summary>
    /// A key the provider marks for encryption is not offered for signature verification: keeping the two
    /// purposes apart is what the <c>use</c> member exists for.
    /// </summary>
    [Fact]
    public async Task SkipsKeysTheProviderMarksForEncryption()
    {
        var handler = new StubHttpMessageHandler(
            KeySetJson(RsaKey("signing-key"), RsaKey("encryption-key", usage: "enc")));

        var keys = await CreateProvider(handler, new FakeTimeProvider())
            .GetSigningKeysAsync(null, TestContext.Current.CancellationToken);

        Assert.Equal("signing-key", Assert.Single(keys).KeyId);
    }

    /// <summary>
    /// A provider that names no key set cannot have its signatures verified, and says so plainly.
    /// </summary>
    [Fact]
    public async Task FailsWhenTheProviderNamesNoKeySet()
    {
        var handler = new StubHttpMessageHandler(KeySetJson(RsaKey("key-one")));

        await Assert.ThrowsAsync<SigningKeysException>(
            () => CreateProvider(handler, new FakeTimeProvider(), keySetUri: null)
                .GetSigningKeysAsync(null, TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A transport failure surfaces as a key-set failure rather than a raw HTTP exception.
    /// </summary>
    [Fact]
    public async Task TranslatesATransportFailure()
    {
        var handler = new StubHttpMessageHandler(string.Empty, HttpStatusCode.ServiceUnavailable);

        var exception = await Assert.ThrowsAsync<SigningKeysException>(
            () => CreateProvider(handler, new FakeTimeProvider())
                .GetSigningKeysAsync(null, TestContext.Current.CancellationToken));

        Assert.IsType<HttpRequestException>(exception.InnerException);
    }
}
