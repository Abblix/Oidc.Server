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

using System.Web;
using Abblix.Oidc.Client.Features.BackChannelAuthentication;
using Abblix.Oidc.Client.Features.ClientAuthentication;
using Abblix.Oidc.Client.Features.Discovery;
using Abblix.Oidc.Client.Features.Tokens;
using Abblix.Oidc.Client.UnitTests.Features.Discovery;
using Abblix.Oidc.Client.UnitTests.Features.Tokens;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Client.UnitTests.Features.BackChannelAuthentication;

/// <summary>
/// What a CIBA authentication request carries, and the two shapes of it the specification rules out.
/// </summary>
public class BackChannelAuthenticationRequestTests
{
    private const string Issuer = "https://provider.example.com";

    /// <summary>
    /// Stands in for the token endpoint, which nothing in this class reaches: what is under test is the
    /// authentication request, and the polling that follows it has its own suite.
    /// </summary>
    private sealed class UnusedTokenEndpoint : ITokenRequestService
    {
        public Task<TokenResponse> ExchangeCodeAsync(
            string code, string codeVerifier, string redirectUri, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public Task<TokenResponse> RefreshAsync(
            string refreshToken, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public Task<TokenResponse> RequestClientCredentialsAsync(
            IReadOnlyCollection<string>? scopes = null, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public Task<TokenResponse> ExchangeTokenAsync(
            TokenExchangeParameters exchange, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public Task<TokenResponse> RedeemDeviceCodeAsync(
            string deviceCode, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public Task<TokenResponse> RedeemAuthenticationRequestAsync(
            string authenticationRequestId, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }

    private const string Acknowledgement = """
                                           {
                                             "auth_req_id": "the-request-id",
                                             "expires_in": 300,
                                             "interval": 5
                                           }
                                           """;

    private static IBackChannelAuthenticationService CreateService(RecordingHttpMessageHandler handler)
        => new BackChannelAuthenticationService(
            new ConfiguredMetadataProvider(new ProviderMetadata
            {
                Issuer = Issuer,
                BackChannelAuthenticationEndpoint = $"{Issuer}/ciba",
            }),
            new StubHttpClientFactory(handler),
            new ClientCredentialsPresenter(
                Options.Create(new OidcClientOptions { ClientId = "test-client" }),
                Options.Create(new ClientAuthenticationOptions { Method = ClientAuthenticationMethods.None })),
            new UnusedTokenEndpoint(),
            TimeProvider.System);

    private static Dictionary<string, string> FormOf(string body)
    {
        var parsed = HttpUtility.ParseQueryString(body);
        return parsed.AllKeys
            .Where(key => key is not null)
            .ToDictionary(key => key!, key => parsed[key]!, StringComparer.Ordinal);
    }

    /// <summary>
    /// The request carries the person named the one way it names them, the scopes asked for, and the
    /// message the person will be shown.
    /// </summary>
    [Fact]
    public async Task TheRequestCarriesTheHintTheScopesAndTheBindingMessage()
    {
        var handler = new RecordingHttpMessageHandler(Acknowledgement);

        var acknowledgement = await CreateService(handler).RequestAsync(
            new BackChannelAuthenticationRequest
            {
                Scopes = ["openid", "profile"],
                LoginHint = "alice@example.com",
                BindingMessage = "W4ZE",
                AcrValues = ["urn:mace:incommon:iap:silver"],
                RequestedExpiry = TimeSpan.FromMinutes(10),
            },
            TestContext.Current.CancellationToken);

        var form = FormOf(handler.LastRequestBody!);
        Assert.Equal("openid profile", form["scope"]);
        Assert.Equal("alice@example.com", form["login_hint"]);
        Assert.Equal("W4ZE", form["binding_message"]);
        Assert.Equal("urn:mace:incommon:iap:silver", form["acr_values"]);

        // Whole seconds, not a formatted TimeSpan: the wire wants a number, and a client that sent
        // "00:10:00" would look correct from here and be unreadable at the other end.
        Assert.Equal("600", form["requested_expiry"]);

        Assert.Equal("the-request-id", acknowledgement.AuthenticationRequestId);
        Assert.Equal(TimeSpan.FromSeconds(5), acknowledgement.PollingInterval);
    }

    /// <summary>
    /// Naming the person twice, or not at all, is refused before anything is sent.
    /// </summary>
    /// <remarks>
    /// CIBA section 7.1: "it is REQUIRED that the Client provides one (and only one) of the hints". Both
    /// halves are worth catching. None means asking the provider to authenticate nobody in particular; two
    /// means handing it a request it cannot resolve, and which of the two it would honour is not something
    /// the specification settles.
    /// </remarks>
    [Theory]
    [InlineData(null, null)]
    [InlineData("alice@example.com", "a.login.hint.token")]
    public async Task ARequestNamingThePersonAnythingButOnceIsRefused(string? loginHint, string? loginHintToken)
    {
        var handler = new RecordingHttpMessageHandler(Acknowledgement);

        await Assert.ThrowsAsync<ArgumentException>(
            () => CreateService(handler).RequestAsync(
                new BackChannelAuthenticationRequest
                {
                    Scopes = ["openid"],
                    LoginHint = loginHint,
                    LoginHintToken = loginHintToken,
                },
                TestContext.Current.CancellationToken));

        Assert.Null(handler.LastRequestBody);
    }

    /// <summary>
    /// A request whose scopes omit <c>openid</c> is refused, because CIBA section 7.1 requires it of every
    /// one of them.
    /// </summary>
    [Fact]
    public async Task ARequestWithoutTheOpenIdScopeIsRefused()
    {
        var handler = new RecordingHttpMessageHandler(Acknowledgement);

        await Assert.ThrowsAsync<ArgumentException>(
            () => CreateService(handler).RequestAsync(
                new BackChannelAuthenticationRequest
                {
                    Scopes = ["profile"],
                    LoginHint = "alice@example.com",
                },
                TestContext.Current.CancellationToken));

        Assert.Null(handler.LastRequestBody);
    }
}
