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

using Abblix.Jwt;
using Abblix.Oidc.Client.Features.SigningKeys;

namespace Abblix.Oidc.Client.UnitTests.Features.SigningKeys;

/// <summary>
/// Tests for <see cref="ConfiguredSigningKeysProvider"/>, the source used when the provider's key set is
/// pinned by the host rather than read from the provider.
/// </summary>
public class ConfiguredSigningKeysProviderTests
{
    private static JsonWebKey KeyWithId(string keyId) => new RsaJsonWebKey { KeyId = keyId };

    /// <summary>
    /// Every configured key is offered when the token names none.
    /// </summary>
    [Fact]
    public async Task ReturnsEveryKeyWhenTheTokenNamesNone()
    {
        var provider = new ConfiguredSigningKeysProvider([KeyWithId("one"), KeyWithId("two")]);

        var keys = await provider.GetSigningKeysAsync(null, TestContext.Current.CancellationToken);

        Assert.Equal(2, keys.Count);
    }

    /// <summary>
    /// A named key is returned alone, so verification does not try keys the token did not name.
    /// </summary>
    [Fact]
    public async Task ReturnsOnlyTheNamedKey()
    {
        var provider = new ConfiguredSigningKeysProvider([KeyWithId("one"), KeyWithId("two")]);

        var keys = await provider.GetSigningKeysAsync("two", TestContext.Current.CancellationToken);

        Assert.Equal("two", Assert.Single(keys).KeyId);
    }

    /// <summary>
    /// A key the token names but the host did not configure leaves every held key on the table rather than
    /// narrowing to nothing. Signature verification makes the final call, exactly as when the set is read
    /// from the provider, so a labelling difference does not become a silent authentication failure.
    /// </summary>
    [Fact]
    public async Task FallsBackToEveryKeyWhenTheNamedOneIsNotConfigured()
    {
        var provider = new ConfiguredSigningKeysProvider([KeyWithId("one"), KeyWithId("two")]);

        var keys = await provider.GetSigningKeysAsync("never-configured", TestContext.Current.CancellationToken);

        Assert.Equal(2, keys.Count);
    }

    /// <summary>
    /// An empty set is refused at construction. Accepting it would produce a client that rejects every token
    /// the provider signs, and does so at the first sign-in rather than at startup.
    /// </summary>
    [Fact]
    public void RefusesAnEmptySet()
    {
        Assert.Throws<SigningKeysException>(() => new ConfiguredSigningKeysProvider([]));
    }
}
