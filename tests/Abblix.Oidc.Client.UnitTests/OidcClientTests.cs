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
using Abblix.Oidc.Client.Features.Authorization.Context;
using Abblix.Oidc.Client.Features.Authorization.Requests;
using Abblix.Oidc.Client.Features.Authorization.Responses;
using Abblix.Oidc.Client.Features.BackChannelLogout;
using Abblix.Oidc.Client.Features.Discovery;
using Abblix.Oidc.Client.Features.EndSession;
using Abblix.Oidc.Client.Features.IdentityTokens;
using Abblix.Oidc.Client.Features.Principal;
using Abblix.Oidc.Client.Features.Revocation;
using Abblix.Oidc.Client.Features.Tokens;
using Abblix.Oidc.Client.Features.UserInfo;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Client.UnitTests;

/// <summary>
/// The compositions the facade adds, and the refusals that live only in them.
/// </summary>
/// <remarks>
/// The happy path is covered where it is worth covering - against a real server, in the end-to-end suite.
/// What is left for here is what a real provider will not do on request: answer one login with two ID Tokens
/// about different people, or return no ID Token at all.
/// </remarks>
public class OidcClientTests
{
    private const string Subject = "248289761001";

    private static JsonWebToken TokenFor(string subject)
    {
        var token = new JsonWebToken();
        token.Payload.Subject = subject;
        return token;
    }

    private sealed class StubResponseHandler(AuthorizationResult result) : IAuthorizationResponseHandler
    {
        public Task<AuthorizationResult> HandleAsync(
            IReadOnlyDictionary<string, IReadOnlyList<string>> parameters,
            CancellationToken cancellationToken = default)
            => Task.FromResult(result);
    }

    /// <summary>
    /// A token-endpoint answer with the members every response carries, so each test states only what it is
    /// about.
    /// </summary>
    private static TokenResponse Tokens(
        string? idToken = null, string? refreshToken = null, int? expiresIn = null)
        => new()
        {
            AccessToken = "the-access-token",
            TokenType = "Bearer",
            IdToken = idToken,
            RefreshToken = refreshToken,
            ExpiresIn = expiresIn,
        };

    private sealed class StubTokenRequestService(TokenResponse response) : ITokenRequestService
    {
        public Task<TokenResponse> ExchangeCodeAsync(
            string code, string codeVerifier, string redirectUri,
            CancellationToken cancellationToken = default)
            => Task.FromResult(response);

        public Task<TokenResponse> RefreshAsync(
            string refreshToken, CancellationToken cancellationToken = default)
            => Task.FromResult(response);

        // The facade composes user-facing operations, and this grant has no user, so nothing here reaches it.
        public Task<TokenResponse> RequestClientCredentialsAsync(
            IReadOnlyCollection<string>? scopes = null, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }

    private sealed class StubIdentityTokenValidator(JsonWebToken token) : IIdentityTokenValidator
    {
        public Task<JsonWebToken> ValidateAsync(
            string identityToken,
            IdentityTokenValidationContext context,
            CancellationToken cancellationToken = default)
            => Task.FromResult(token);
    }

    private static AuthorizationContext Context() => new()
    {
        State = "the-state",
        Nonce = "the-nonce",
        CodeVerifier = "the-verifier",
        ReturnUri = "/home",
        Issuer = "https://provider.example.com",
        RedirectUri = "https://client.example.com/cb",
    };

    private static IOidcClient Create(
        AuthorizationResult response,
        TokenResponse tokens,
        JsonWebToken tokenEndpointIdentityToken)
        => new OidcClient(
            new ConfiguredMetadataProvider(new ProviderMetadata
            {
                Issuer = "https://provider.example.com",
                CheckSessionIframe = "https://provider.example.com/check-session",
            }),
            Options.Create(new OidcClientOptions { ClientId = "test-client" }),
            new UnusedRequestBuilder(),
            new StubResponseHandler(response),
            new StubTokenRequestService(tokens),
            new StubIdentityTokenValidator(tokenEndpointIdentityToken),
            new ClaimsPrincipalFactory(Options.Create(new ClaimsPrincipalOptions())),
            new UnusedUserInfoService(),
            new UnusedRevocationService(),
            new UnusedEndSessionRequestBuilder(),
            new UnusedLogoutTokenValidator());

    /// <summary>
    /// A code-flow callback produces a signed-in user carrying what the login yielded.
    /// </summary>
    [Fact]
    public async Task ACodeCallbackSignsTheUserIn()
    {
        var client = Create(
            new AuthorizationResult(Context()) { Code = "the-code" },
            Tokens("the.id.token", "the-refresh-token", 3600),
            TokenFor(Subject));

        var signIn = await client.HandleCallbackAsync(
            new Dictionary<string, IReadOnlyList<string>>(), TestContext.Current.CancellationToken);

        Assert.Equal(Subject, signIn.Principal.Identity?.Name);
        Assert.Equal("the.id.token", signIn.EncodedIdentityToken);
        Assert.Equal("the-refresh-token", signIn.RefreshToken);
        Assert.Equal(TimeSpan.FromHours(1), signIn.ExpiresIn);
        Assert.Equal("/home", signIn.ReturnUri);
    }

    /// <summary>
    /// Two ID Tokens describing different people is a login that identifies nobody, so it is refused rather
    /// than resolved by picking one.
    /// </summary>
    /// <remarks>
    /// Only the hybrid flow can produce the pair. Each token is valid on its own terms - same issuer, same
    /// audience, same nonce - so nothing before this point has any reason to object.
    /// </remarks>
    [Fact]
    public async Task TwoIdentityTokensAboutDifferentPeopleAreRefused()
    {
        var client = Create(
            new AuthorizationResult(Context())
            {
                Code = "the-code",
                IdToken = TokenFor("somebody-else"),
                EncodedIdToken = "front.channel.token",
            },
            Tokens("the.id.token"),
            TokenFor(Subject));

        await Assert.ThrowsAsync<IdentityTokenValidationException>(
            () => client.HandleCallbackAsync(
                new Dictionary<string, IReadOnlyList<string>>(), TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// The same pair naming the same person is what a conformant provider sends, and it signs in.
    /// </summary>
    [Fact]
    public async Task TwoIdentityTokensAboutOnePersonAreAccepted()
    {
        var client = Create(
            new AuthorizationResult(Context())
            {
                Code = "the-code",
                IdToken = TokenFor(Subject),
                EncodedIdToken = "front.channel.token",
            },
            Tokens("the.id.token"),
            TokenFor(Subject));

        var signIn = await client.HandleCallbackAsync(
            new Dictionary<string, IReadOnlyList<string>>(), TestContext.Current.CancellationToken);

        Assert.Equal(Subject, signIn.Principal.Identity?.Name);
    }

    /// <summary>
    /// A token endpoint answering without an ID Token leaves no authenticated user, which is a failure and
    /// not a sign-in with an empty principal.
    /// </summary>
    [Fact]
    public async Task NoIdentityTokenIsAFailure()
    {
        var client = Create(
            new AuthorizationResult(Context()) { Code = "the-code" },
            Tokens(),
            TokenFor(Subject));

        await Assert.ThrowsAsync<TokenRequestException>(
            () => client.HandleCallbackAsync(
                new Dictionary<string, IReadOnlyList<string>>(), TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A response carrying neither a code nor an ID Token cannot sign anybody in.
    /// </summary>
    [Fact]
    public async Task NeitherCodeNorIdentityTokenIsAFailure()
    {
        var client = Create(
            new AuthorizationResult(Context()) { AccessToken = "the-access-token" },
            Tokens(),
            TokenFor(Subject));

        await Assert.ThrowsAsync<AuthorizationResponseException>(
            () => client.HandleCallbackAsync(
                new Dictionary<string, IReadOnlyList<string>>(), TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A front-channel sign-in reports no refresh token, because one never travels through the browser.
    /// </summary>
    [Fact]
    public async Task AFrontChannelSignInCarriesNoRefreshToken()
    {
        var client = Create(
            new AuthorizationResult(Context())
            {
                IdToken = TokenFor(Subject),
                EncodedIdToken = "front.channel.token",
                AccessToken = "the-access-token",
            },
            Tokens(),
            TokenFor(Subject));

        var signIn = await client.HandleCallbackAsync(
            new Dictionary<string, IReadOnlyList<string>>(), TestContext.Current.CancellationToken);

        Assert.Null(signIn.RefreshToken);
        Assert.Equal("the-access-token", signIn.AccessToken);
        Assert.Equal("front.channel.token", signIn.EncodedIdentityToken);
    }

    private sealed class UnusedRequestBuilder : IAuthorizationRequestBuilder
    {
        public Task<AuthorizationRequest> CreateAsync(
            Uri returnUri,
            AuthorizationRequestParameters? parameters = null,
            CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }

    private sealed class UnusedUserInfoService : IUserInfoService
    {
        public Task<JsonObject> GetAsync(
            string accessToken, string expectedSubject, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }

    private sealed class UnusedRevocationService : ITokenRevocationService
    {
        public Task RevokeAsync(
            string token, string? tokenTypeHint = null, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }

    private sealed class UnusedEndSessionRequestBuilder : IEndSessionRequestBuilder
    {
        public Task<Uri> CreateAsync(
            string identityToken,
            string? state = null,
            string? logoutHint = null,
            CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }

    private sealed class UnusedLogoutTokenValidator : ILogoutTokenValidator
    {
        public Task<LogoutNotification> ValidateAsync(
            string logoutToken, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }

    /// <summary>
    /// The session check carries the three values a watching page needs, and the message with the single
    /// space section 3.1 defines.
    /// </summary>
    [Fact]
    public async Task TheSessionCheckSpellsTheMessage()
    {
        var client = Create(
            new AuthorizationResult(Context()) { Code = "the-code" },
            Tokens("the.id.token"),
            TokenFor(Subject));

        var check = await client.CreateSessionCheckAsync(
            "the-session-state", TestContext.Current.CancellationToken);

        Assert.NotNull(check);
        Assert.Equal("https://provider.example.com/check-session", check.CheckSessionIframe);
        Assert.Equal("test-client the-session-state", check.Message);
    }

    /// <summary>
    /// The login state from the authorization response reaches the host, since it is what a watching page
    /// polls with.
    /// </summary>
    [Fact]
    public async Task TheSessionStateReachesTheHost()
    {
        var client = Create(
            new AuthorizationResult(Context())
            {
                Code = "the-code",
                SessionState = "the-session-state",
            },
            Tokens("the.id.token"),
            TokenFor(Subject));

        var signIn = await client.HandleCallbackAsync(
            new Dictionary<string, IReadOnlyList<string>>(), TestContext.Current.CancellationToken);

        Assert.Equal("the-session-state", signIn.SessionState);
    }
}
