// Abblix OIDC Client Library
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
using Abblix.Oidc.Client.Features.Discovery;
using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Client.E2E.Tests;

/// <summary>
/// RFC 8414 section 2.1 signed metadata, produced by the real provider and consumed by this client.
/// </summary>
/// <remarks>
/// The unit suite signs its own bundles, so it can only prove the client is self-consistent: the same hand
/// writes the document and the code that reads it. What is in question here is the seam - whether the
/// provider's <c>signed_metadata</c> carries the members this client merges, and whether its <c>iss</c>
/// claim names what this client requires it to name. Neither is answerable against a bundle we mint.
///
/// The provider is told which key to sign with, and the client is given the public half directly rather than
/// through the document. That is the arrangement the feature exists for, and it is also what makes the
/// negative case below meaningful.
/// </remarks>
public class SignedMetadataTests
{
    /// <summary>
    /// The provider's signing key. The test holds it, so the client can be given the public half by a route
    /// that does not pass through the document being verified.
    /// </summary>
    private static readonly JsonWebKey ProviderKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);

    private static readonly JsonWebKey StrangersKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);

    private static ClientAgainstServerFixture CreateProvider(bool signsMetadata) => new()
    {
        ConfigureProviderServices = services => services.PostConfigure<OidcOptions>(options =>
        {
            options.SigningKeys = [ProviderKey];
            options.Discovery.SignedMetadata = signsMetadata;
        }),
    };

    private static async Task<ProviderMetadata> ReadMetadataAsync(
        ClientAgainstServerFixture fixture, JsonWebKey pinnedKey, CancellationToken cancellationToken)
    {
        fixture.ConfigureClientServices = services =>
            services.AddSignedMetadataVerification([pinnedKey.Sanitize(includePrivateKeys: false)]);

        await using var client = fixture.CreateOidcClient();
        return await client.GetRequiredService<IProviderMetadataProvider>()
            .GetMetadataAsync(cancellationToken);
    }

    /// <summary>
    /// A document the provider signed with the pinned key is accepted, and the endpoints the client goes on
    /// to use are the ones it carries.
    /// </summary>
    [Fact]
    public async Task TheProvidersOwnSignedMetadataIsAccepted()
    {
        var fixture = CreateProvider(signsMetadata: true);
        await using var _ = fixture;
        await fixture.InitializeAsync();

        var metadata = await ReadMetadataAsync(fixture, ProviderKey, TestContext.Current.CancellationToken);

        Assert.Equal(ClientAgainstServerFixture.Issuer, metadata.Issuer);
        Assert.Equal($"{ClientAgainstServerFixture.Issuer}/connect/token", metadata.TokenEndpoint);
    }

    /// <summary>
    /// The same document is refused when the key the host pinned is not the one the provider signed with.
    /// </summary>
    /// <remarks>
    /// Without this case the one above would pass against a client that never checked the signature at all,
    /// which is the state this feature was added from.
    /// </remarks>
    [Fact]
    public async Task AProviderSigningWithAnotherKeyIsRefused()
    {
        var fixture = CreateProvider(signsMetadata: true);
        await using var _ = fixture;
        await fixture.InitializeAsync();

        await Assert.ThrowsAsync<ProviderMetadataException>(
            () => ReadMetadataAsync(fixture, StrangersKey, TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A provider that publishes no signed metadata is refused by a host that asked for it, against the real
    /// document rather than a hand-built one missing the member.
    /// </summary>
    [Fact]
    public async Task AProviderThatDoesNotSignIsRefused()
    {
        var fixture = CreateProvider(signsMetadata: false);
        await using var _ = fixture;
        await fixture.InitializeAsync();

        var exception = await Assert.ThrowsAsync<ProviderMetadataException>(
            () => ReadMetadataAsync(fixture, ProviderKey, TestContext.Current.CancellationToken));

        Assert.Contains("no signed_metadata", exception.Message);
    }
}
