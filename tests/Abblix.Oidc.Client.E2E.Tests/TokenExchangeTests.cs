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

using System.Net;
using Abblix.Oidc.Client.Features.Tokens;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Client.E2E.Tests;

/// <summary>
/// RFC 8693 token exchange against the real provider, starting from a token the provider itself issued.
/// </summary>
/// <remarks>
/// The subject token has to be genuine for any of this to mean anything: a provider asked to exchange a
/// string this suite invented would refuse it on the token, not on the exchange, and the test would pass for
/// the wrong reason. So each case runs the authorization-code flow first and presents what came back.
/// </remarks>
public class TokenExchangeTests(ClientAgainstServerFixture fixture) : IClassFixture<ClientAgainstServerFixture>
{
    /// <summary>
    /// The provider takes the access token it issued and gives another in its place, saying what kind it
    /// issued as RFC 8693 section 2.2.1 requires.
    /// </summary>
    [Fact]
    public async Task ThePresentedTokenIsExchangedForAnother()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var client = fixture.CreateOidcClient();

        var accessToken = await SignInForAnAccessTokenAsync(client, cancellationToken);

        var exchanged = await client.GetRequiredService<ITokenRequestService>().ExchangeTokenAsync(
            new TokenExchangeParameters
            {
                SubjectToken = accessToken,
                SubjectTokenType = TokenExchangeTokenTypes.AccessToken,
            },
            cancellationToken);

        Assert.NotEmpty(exchanged.AccessToken);
        Assert.NotEqual(accessToken, exchanged.AccessToken);
        Assert.Equal(TokenExchangeTokenTypes.AccessToken, exchanged.IssuedTokenType);
    }

    /// <summary>
    /// A subject token the provider did not issue is refused.
    /// </summary>
    /// <remarks>
    /// Without this the case above would pass against a provider that hands out a token to anyone who asks,
    /// and the exchange would be proving nothing about the token presented.
    /// </remarks>
    [Fact]
    public async Task ATokenTheProviderDidNotIssueIsRefused()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var client = fixture.CreateOidcClient();

        var exception = await Assert.ThrowsAsync<TokenRequestException>(
            () => client.GetRequiredService<ITokenRequestService>().ExchangeTokenAsync(
                new TokenExchangeParameters
                {
                    SubjectToken = "not-a-token-this-provider-issued",
                    SubjectTokenType = TokenExchangeTokenTypes.AccessToken,
                },
                cancellationToken));

        Assert.NotNull(exception.Error);
    }

    /// <summary>
    /// Runs the authorization-code flow and returns the access token the provider issued.
    /// </summary>
    private async Task<string> SignInForAnAccessTokenAsync(
        IServiceProvider client, CancellationToken cancellationToken)
    {
        var request = await client.GetRequiredService<IOidcClient>()
            .CreateAuthorizationRequestAsync(
                new Uri("/home", UriKind.Relative), cancellationToken: cancellationToken);

        using var browser = fixture.CreateBrowser();
        using var response = await browser.GetAsync(request.RequestUri, cancellationToken);

        Assert.True(
            response.StatusCode is HttpStatusCode.Found or HttpStatusCode.SeeOther,
            $"Expected a redirect to the callback, got {(int)response.StatusCode}.");

        var location = response.Headers.Location;
        Assert.NotNull(location);

        var callback = ClientHostFixture.QueryOf(location);

        var signIn = await client.GetRequiredService<IOidcClient>()
            .HandleCallbackAsync(callback, cancellationToken);

        Assert.NotNull(signIn.AccessToken);
        return signIn.AccessToken;
    }
}
