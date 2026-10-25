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

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Client.Features.Discovery;
using Abblix.Oidc.Client.Features.TokenValidation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Client.UnitTests.Features.Discovery;

/// <summary>
/// RFC 8414 section 2.1 signed metadata, exercised through <see cref="DiscoveredMetadataProvider"/> rather
/// than against the verifier alone.
/// </summary>
/// <remarks>
/// The composition is half of what these cases are about. Verification has to happen before the document is
/// parsed and before the issuer is checked, and a verifier tested on its own would pass every case here while
/// the provider went on acting upon the published values.
///
/// Each document differs from a valid one in exactly one respect, so a passing rejection says which check
/// did the rejecting.
/// </remarks>
public class SignedMetadataTests
{
    private const string Authority = "https://provider.example.com";

    private static readonly JsonWebKey MetadataKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);
    private static readonly JsonWebKey OtherKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);

    private static readonly IServiceProvider Jwt = new ServiceCollection()
        .AddSingleton(TimeProvider.System)
        .AddLogging()
        .AddJsonWebTokens()
        .BuildServiceProvider();

    /// <summary>
    /// The document as the provider publishes it, before anything is signed: the endpoints here are the ones
    /// a client acting on plain JSON would use.
    /// </summary>
    private static JsonObject PublishedDocument(string tokenEndpoint) => new()
    {
        ["issuer"] = Authority,
        ["authorization_endpoint"] = $"{Authority}/authorize",
        ["token_endpoint"] = tokenEndpoint,
        ["jwks_uri"] = $"{Authority}/jwks",
        ["a_member_this_client_does_not_model"] = "kept",
    };

    /// <summary>
    /// Signs <paramref name="bundle"/> the way a provider does, and hangs it on <paramref name="document"/>
    /// under <c>signed_metadata</c>.
    /// </summary>
    private static async Task<JsonObject> WithSignedMetadata(
        JsonObject document, JsonObject bundle, string attestedBy = Authority, JsonWebKey? key = null)
    {
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload = new JsonWebTokenPayload(bundle)
            {
                Issuer = attestedBy,
                IssuedAt = TimeProvider.System.GetUtcNow(),
            },
        };

        document["signed_metadata"] = await Jwt.GetRequiredService<IJsonWebTokenCreator>()
            .IssueAsync(token, key ?? MetadataKey);

        return document;
    }

    private static DiscoveredMetadataProvider CreateProvider(JsonObject document, bool pinKeys)
    {
        ISignedMetadataVerifier verifier = pinKeys
            ? new SignedMetadataVerifier(
                Jwt.GetRequiredService<IJsonWebTokenValidator>(),
                [MetadataKey],
                Options.Create(new ProviderTokenValidationOptions()))
            : new NoSignedMetadataVerifier();

        return new DiscoveredMetadataProvider(
            new StubHttpClientFactory(new StubHttpMessageHandler(document.ToJsonString())),
            verifier,
            TimeProvider.System,
            Options.Create(new DiscoveryOptions { Authority = new Uri(Authority) }));
    }

    private static Task<ProviderMetadata> Read(JsonObject document, bool pinKeys = true)
        => CreateProvider(document, pinKeys).GetMetadataAsync(TestContext.Current.CancellationToken);

    private static async Task<ProviderMetadataException> AssertRefuses(JsonObject document)
        => await Assert.ThrowsAsync<ProviderMetadataException>(() => Read(document));

    /// <summary>
    /// The signed bundle wins over the published JSON, which is the whole of RFC 8414 section 2.1: "metadata
    /// values conveyed in the signed metadata MUST take precedence over the corresponding values conveyed
    /// using plain JSON elements".
    /// </summary>
    /// <remarks>
    /// Stated as the attack it answers rather than as a preference: the published document names an endpoint
    /// under someone else's control, and what decides where this client sends its authorization code is the
    /// bundle the provider signed.
    /// </remarks>
    [Fact]
    public async Task ASignedValueOverridesThePublishedOne()
    {
        var document = await WithSignedMetadata(
            PublishedDocument(tokenEndpoint: "https://attacker.example.com/token"),
            new JsonObject { ["token_endpoint"] = $"{Authority}/token" });

        var metadata = await Read(document);

        Assert.Equal($"{Authority}/token", metadata.TokenEndpoint);
    }

    /// <summary>
    /// Members the bundle says nothing about keep the values the provider published. Precedence applies per
    /// value, so a bundle asserting one endpoint must not blank out the rest of the document.
    /// </summary>
    [Fact]
    public async Task APublishedValueTheBundleIsSilentAboutSurvives()
    {
        var document = await WithSignedMetadata(
            PublishedDocument($"{Authority}/token"),
            new JsonObject { ["token_endpoint"] = $"{Authority}/token" });

        var metadata = await Read(document);

        Assert.Equal($"{Authority}/authorize", metadata.AuthorizationEndpoint);
        Assert.Equal($"{Authority}/jwks", metadata.JsonWebKeySetUri);
    }

    /// <summary>
    /// A host that pinned keys is refused a document carrying no signed metadata at all.
    /// </summary>
    /// <remarks>
    /// Falling back to the published values would make the whole feature strippable by anyone who can remove
    /// one member, which is exactly the party it exists to defend against.
    /// </remarks>
    [Fact]
    public async Task ADocumentWithoutSignedMetadataIsRefused()
    {
        var exception = await AssertRefuses(PublishedDocument($"{Authority}/token"));

        Assert.Contains("no signed_metadata", exception.Message);
    }

    /// <summary>
    /// A bundle signed by a key the host does not hold is refused, which is what makes the pinning mean
    /// anything.
    /// </summary>
    [Fact]
    public async Task ABundleSignedByAnotherKeyIsRefused()
    {
        var document = await WithSignedMetadata(
            PublishedDocument($"{Authority}/token"),
            new JsonObject { ["token_endpoint"] = $"{Authority}/token" },
            key: OtherKey);

        await AssertRefuses(document);
    }

    /// <summary>
    /// The <c>iss</c> claim must name the provider the effective document names. RFC 8414 section 2.1 has it
    /// denote "the party attesting to the claims in the signed metadata", and this client accepts only the
    /// provider attesting for itself.
    /// </summary>
    [Fact]
    public async Task ABundleAttestedByAnotherPartyIsRefused()
    {
        var document = await WithSignedMetadata(
            PublishedDocument($"{Authority}/token"),
            new JsonObject { ["token_endpoint"] = $"{Authority}/token" },
            attestedBy: "https://federation.example.org");

        var exception = await AssertRefuses(document);

        Assert.Contains("attested by", exception.Message);
    }

    /// <summary>
    /// A bundle that restates the issuer is checked against the authority the document was fetched from, the
    /// same as a published one is.
    /// </summary>
    /// <remarks>
    /// This is the case the ordering exists for. The bundle is signed by the pinned key and is internally
    /// consistent - it names the same issuer in the metadata and in <c>iss</c> - so nothing about it is
    /// detectably wrong until the effective document meets the authority it was read from. Were the issuer
    /// checked before the merge, this would pass on the published identifier and then be acted upon under the
    /// signed one.
    /// </remarks>
    [Fact]
    public async Task ASignedIssuerThatDoesNotMatchTheAuthorityIsRefused()
    {
        const string otherIssuer = "https://elsewhere.example.com";

        var document = await WithSignedMetadata(
            PublishedDocument($"{Authority}/token"),
            new JsonObject { ["issuer"] = otherIssuer },
            attestedBy: otherIssuer);

        var exception = await AssertRefuses(document);

        Assert.Contains("does not match the configured authority", exception.Message);
    }

    /// <summary>
    /// Without pinned keys the client acts on the document as published and ignores the bundle.
    /// </summary>
    /// <remarks>
    /// The default, and a deliberate one: the keys that could verify the bundle would have to be named by the
    /// same document, so the signature would attest to nothing the document does not already claim. Recorded
    /// as a test because it is the behaviour a host gets without asking, and a silent change to it would
    /// change what every existing deployment trusts.
    /// </remarks>
    [Fact]
    public async Task WithoutPinnedKeysTheBundleIsIgnored()
    {
        var document = await WithSignedMetadata(
            PublishedDocument(tokenEndpoint: "https://published.example.com/token"),
            new JsonObject { ["token_endpoint"] = $"{Authority}/token" });

        var metadata = await Read(document, pinKeys: false);

        Assert.Equal("https://published.example.com/token", metadata.TokenEndpoint);
    }
}
