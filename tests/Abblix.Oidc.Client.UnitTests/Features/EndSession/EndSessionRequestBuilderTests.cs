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

using Abblix.Oidc.Client.Features.Discovery;
using Abblix.Oidc.Client.Features.EndSession;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Client.UnitTests.Features.EndSession;

/// <summary>
/// Building the address that ends the user's session at the provider.
/// </summary>
public class EndSessionRequestBuilderTests
{
    private const string Issuer = "https://provider.example.com";
    private const string EndSessionEndpoint = $"{Issuer}/end-session";
    private const string IdentityToken = "the.id.token";

    private static EndSessionRequestBuilder CreateBuilder(
        Action<EndSessionRequestOptions>? configure = null,
        string? endSessionEndpoint = EndSessionEndpoint)
    {
        var metadata = new ProviderMetadata { Issuer = Issuer, EndSessionEndpoint = endSessionEndpoint };

        var options = new EndSessionRequestOptions();
        configure?.Invoke(options);

        return new EndSessionRequestBuilder(
            new ConfiguredMetadataProvider(metadata),
            Options.Create(new OidcClientOptions { ClientId = "test-client" }),
            Options.Create(options));
    }

    /// <summary>
    /// The hint travels, because without it the user is asked to confirm. RP-Initiated Logout 1.0 section 6:
    /// "Logout requests without a valid id_token_hint value are a potential means of denial of service;
    /// therefore, OPs should obtain explicit confirmation from the End-User before acting upon them."
    /// </summary>
    [Fact]
    public async Task SendsTheIdentityTokenAsTheHint()
    {
        var uri = await CreateBuilder().CreateAsync(
            IdentityToken, cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(IdentityToken, Wire.QueryOf(uri)["id_token_hint"]);
    }

    /// <summary>
    /// The client names itself alongside the hint, which section 2 both permits and puts to work: "When both
    /// client_id and id_token_hint are present, the OP MUST verify that the Client Identifier matches the one
    /// used when issuing the ID Token."
    /// </summary>
    [Fact]
    public async Task NamesTheClient()
    {
        var uri = await CreateBuilder().CreateAsync(
            IdentityToken, cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal("test-client", Wire.QueryOf(uri)["client_id"]);
    }

    /// <summary>
    /// The configured post-logout address and language preferences are sent when set.
    /// </summary>
    [Fact]
    public async Task SendsThePostLogoutAddressAndLocales()
    {
        var builder = CreateBuilder(options =>
        {
            options.PostLogoutRedirectUri = new Uri("https://client.example.com/signed-out");
            options.UiLocales.Add("fr-CA");
            options.UiLocales.Add("en");
        });

        var query = Wire.QueryOf(await builder.CreateAsync(
            IdentityToken, cancellationToken: TestContext.Current.CancellationToken));

        Assert.Equal("https://client.example.com/signed-out", query["post_logout_redirect_uri"]);
        Assert.Equal("fr-CA en", query["ui_locales"]);
    }

    /// <summary>
    /// Optional parameters the caller did not supply are left out rather than sent empty, so the provider
    /// sees the request the caller meant.
    /// </summary>
    [Fact]
    public async Task OmitsWhatWasNotAskedFor()
    {
        var query = Wire.QueryOf(await CreateBuilder().CreateAsync(
            IdentityToken, cancellationToken: TestContext.Current.CancellationToken));

        Assert.False(query.ContainsKey("state"));
        Assert.False(query.ContainsKey("logout_hint"));
        Assert.False(query.ContainsKey("post_logout_redirect_uri"));
        Assert.False(query.ContainsKey("ui_locales"));
    }

    /// <summary>
    /// The caller's state and logout hint are forwarded untouched. Section 2 on state: "if included in the
    /// logout request, the OP passes this value back to the RP using the state parameter".
    /// </summary>
    [Fact]
    public async Task ForwardsTheCallerStateAndHint()
    {
        var uri = await CreateBuilder().CreateAsync(
            IdentityToken, "opaque-state", "user@example.com", TestContext.Current.CancellationToken);

        var query = Wire.QueryOf(uri);
        Assert.Equal("opaque-state", query["state"]);
        Assert.Equal("user@example.com", query["logout_hint"]);
    }

    /// <summary>
    /// Parameters the provider already published on its endpoint survive, because a provider is free to put
    /// them there and dropping them would break it.
    /// </summary>
    [Fact]
    public async Task KeepsTheEndpointsOwnQuery()
    {
        var builder = CreateBuilder(endSessionEndpoint: $"{EndSessionEndpoint}?tenant=acme");

        var query = Wire.QueryOf(await builder.CreateAsync(
            IdentityToken, cancellationToken: TestContext.Current.CancellationToken));

        Assert.Equal("acme", query["tenant"]);
        Assert.Equal(IdentityToken, query["id_token_hint"]);
    }

    /// <summary>
    /// A relative post-logout address is refused. The browser resolves it from the provider's page, so it
    /// would land the user on the provider's site instead of back here.
    /// </summary>
    [Fact]
    public async Task ARelativePostLogoutAddressIsRefused()
    {
        var builder = CreateBuilder(options =>
            options.PostLogoutRedirectUri = new Uri("/signed-out", UriKind.Relative));

        await Assert.ThrowsAsync<EndSessionRequestException>(
            () => builder.CreateAsync(
                IdentityToken, cancellationToken: TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A provider publishing no end-session endpoint is named as the reason, rather than producing an
    /// address to nowhere.
    /// </summary>
    [Fact]
    public async Task AProviderWithNoEndSessionEndpointIsRefused()
    {
        var builder = CreateBuilder(endSessionEndpoint: null);

        await Assert.ThrowsAsync<EndSessionRequestException>(
            () => builder.CreateAsync(
                IdentityToken, cancellationToken: TestContext.Current.CancellationToken));
    }
}
