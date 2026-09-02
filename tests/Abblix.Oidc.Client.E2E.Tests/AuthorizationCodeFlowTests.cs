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
using Abblix.Oidc.Client.Features.Authorization.Requests;
using Abblix.Oidc.Client.Features.Authorization.Responses;
using Abblix.Oidc.Client.Features.Discovery;
using Abblix.Oidc.Client.Features.IdentityTokens;
using Abblix.Oidc.Client.Features.Revocation;
using Abblix.Oidc.Client.Features.Tokens;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Client.E2E.Tests;

/// <summary>
/// The authorization code flow, driven by the Abblix client against a real Abblix server.
/// </summary>
/// <remarks>
/// Every check here has a unit test behind it. What those cannot say is whether the two halves agree: the
/// stubs a unit suite talks to were written by the same hand as the code under test, so a wrong assumption
/// about a response shape, a parameter name or an ordering is reproduced identically on both sides and the
/// test still passes. This suite removes that agreement.
/// </remarks>
public class AuthorizationCodeFlowTests(ClientAgainstServerFixture fixture)
{
    /// <summary>
    /// The subject the test host authenticates every visitor as.
    /// </summary>
    private const string Subject = "e2e-subject";

    /// <summary>
    /// Sends the authorization request the way a browser would, and returns the callback parameters the
    /// provider redirected to.
    /// </summary>
    /// <remarks>
    /// The host authenticates and consents on its own, so the redirect carrying the code comes back from
    /// the first request. Redirects are not followed: the callback address belongs to the client, and the
    /// point is to read what the provider put on it.
    /// </remarks>
    private async Task<IReadOnlyDictionary<string, IReadOnlyList<string>>> FollowAsync(
        Uri authorizationRequest, CancellationToken cancellationToken)
    {
        using var browser = fixture.CreateBrowser();

        using var response = await browser.GetAsync(authorizationRequest, cancellationToken);

        // Which redirect status the provider picks is its business - OAuth 2.0 for Browser-Based
        // Applications and OIDC Core both leave it open, and a client that pinned one would break against a
        // conformant provider that picked the other.
        Assert.True(
            response.StatusCode is HttpStatusCode.Found or HttpStatusCode.SeeOther,
            $"Expected a redirect to the callback, got {(int)response.StatusCode}.");

        var location = response.Headers.Location;
        Assert.NotNull(location);
        Assert.StartsWith(ClientAgainstServerFixture.RedirectUri, location.OriginalString, StringComparison.Ordinal);

        return ClientHostFixture.QueryOf(location);
    }

    /// <summary>
    /// The provider publishes the endpoints this client needs, and declares itself as the issuer the client
    /// asked for.
    /// </summary>
    [Fact]
    public async Task TheProviderIsDiscovered()
    {
        await using var client = fixture.CreateOidcClient();

        var metadata = await client.GetRequiredService<IProviderMetadataProvider>()
            .GetMetadataAsync(TestContext.Current.CancellationToken);

        Assert.Equal(ClientAgainstServerFixture.Issuer, metadata.Issuer);
        Assert.NotNull(metadata.AuthorizationEndpoint);
        Assert.NotNull(metadata.TokenEndpoint);
        Assert.NotNull(metadata.UserInfoEndpoint);
    }

    /// <summary>
    /// The whole flow, end to end: the client builds an authorization request, the provider answers it, the
    /// client accepts the callback, redeems the code, and validates the ID Token it gets back.
    /// </summary>
    [Fact]
    public async Task TheCodeFlowCompletesAndTheIdentityTokenValidates()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var client = fixture.CreateOidcClient();

        var request = await client.GetRequiredService<IAuthorizationRequestBuilder>()
            .CreateAsync(new Uri(ClientAgainstServerFixture.ReturnPath, UriKind.Relative), cancellationToken: cancellationToken);

        var callback = await FollowAsync(request.RequestUri, cancellationToken);

        var result = await client.GetRequiredService<IAuthorizationResponseHandler>()
            .HandleAsync(callback, cancellationToken);

        Assert.NotNull(result.Code);

        var tokens = await client.GetRequiredService<ITokenRequestService>().ExchangeCodeAsync(
            result.Code, result.Context.CodeVerifier, result.Context.RedirectUri, cancellationToken);

        Assert.NotNull(tokens.AccessToken);
        Assert.NotNull(tokens.IdToken);

        var identityToken = await client.GetRequiredService<IIdentityTokenValidator>().ValidateAsync(
            tokens.IdToken,
            new IdentityTokenValidationContext
            {
                Nonce = result.Context.Nonce,
                AccessToken = tokens.AccessToken,
            },
            cancellationToken);

        Assert.Equal(Subject, identityToken.Payload.Subject);
        Assert.Equal(ClientAgainstServerFixture.Issuer, identityToken.Payload.Issuer);
    }

    /// <summary>
    /// Asking how recent the authentication must be reaches the provider, and the answer is checked rather
    /// than taken on trust.
    /// </summary>
    /// <remarks>
    /// The interop fact is the one a unit suite cannot state. OIDC Core 1.0 section 3.1.2.1 puts an
    /// obligation on the provider that the client's whole check rests on: "When max_age is used, the ID
    /// Token returned MUST include an auth_time Claim Value". A stub written by this hand would return
    /// whatever it was told to; a real provider either honours the parameter or does not, and the client's
    /// refusal of a token without <c>auth_time</c> only means something if a conformant provider supplies
    /// one when asked.
    /// The validation is driven with the stored request rather than a hand-built context, so what is
    /// exercised is the round trip the client actually performs: the parameter went out with the redirect,
    /// waited in the store while the user was away, and came back to be compared against the answer.
    /// What this cannot exercise is the refusal itself. The provider authenticates the visitor on the spot,
    /// so its <c>auth_time</c> is always fresh and no honest arrangement here produces a stale one; the
    /// refusal path belongs to the validator's own suite, which owns the clock.
    /// </remarks>
    [Fact]
    public async Task AskingHowRecentTheAuthenticationMustBeIsHonouredAndChecked()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var client = fixture.CreateOidcClient();

        var maxAge = TimeSpan.FromMinutes(5);

        var request = await client.GetRequiredService<IAuthorizationRequestBuilder>().CreateAsync(
            new Uri(ClientAgainstServerFixture.ReturnPath, UriKind.Relative),
            new AuthorizationRequestParameters { MaxAge = maxAge },
            cancellationToken);

        Assert.Contains("max_age=300", request.RequestUri.Query, StringComparison.Ordinal);
        Assert.Equal(maxAge, request.Context.MaxAge);

        var callback = await FollowAsync(request.RequestUri, cancellationToken);

        var result = await client.GetRequiredService<IAuthorizationResponseHandler>()
            .HandleAsync(callback, cancellationToken);

        Assert.NotNull(result.Code);

        var tokens = await client.GetRequiredService<ITokenRequestService>().ExchangeCodeAsync(
            result.Code, result.Context.CodeVerifier, result.Context.RedirectUri, cancellationToken);

        Assert.NotNull(tokens.IdToken);

        var identityToken = await client.GetRequiredService<IIdentityTokenValidator>().ValidateAsync(
            tokens.IdToken,
            new IdentityTokenValidationContext
            {
                Nonce = result.Context.Nonce,
                MaxAge = result.Context.MaxAge,
                AcceptableAuthenticationContextClassReferences = result.Context.AcrValues,
            },
            cancellationToken);

        // The claim the provider owes for having been asked. Without it the validation above would have
        // thrown, so this states what the provider supplied rather than merely that nothing went wrong.
        Assert.NotNull(identityToken.Payload.AuthenticationTime);
    }

    /// <summary>
    /// The claims the UserInfo endpoint returns are about the user this login authenticated, which is the
    /// check OpenID Connect Core 1.0 section 5.3.2 puts on the client and which only a real provider can
    /// exercise.
    /// </summary>
    [Fact]
    public async Task UserInfoAnswersForTheSameSubject()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var client = fixture.CreateOidcClient();

        var signIn = await SignInAsync(client, cancellationToken);

        // The principal the host would sign in with, built from the ID Token this login produced.
        Assert.Equal(Subject, signIn.Principal.Identity?.Name);
        Assert.True(signIn.Principal.Identity?.IsAuthenticated);

        // Said out loud rather than assumed: a login that produced no access token cannot be asked about the
        // user, and naming that beats a null reference thrown from inside the call.
        Assert.NotNull(signIn.AccessToken);

        var claims = await client.GetRequiredService<IOidcClient>()
            .GetUserInfoAsync(signIn.AccessToken, Subject, cancellationToken);

        Assert.Equal(Subject, claims["sub"]?.GetValue<string>());
    }

    /// <summary>
    /// A token this client holds is revoked by the provider on request (RFC 7009).
    /// </summary>
    [Fact]
    public async Task ARefreshTokenIsRevoked()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var client = fixture.CreateOidcClient();

        var signIn = await SignInAsync(client, cancellationToken);
        Assert.NotNull(signIn.RefreshToken);

        await client.GetRequiredService<IOidcClient>().RevokeAsync(
            signIn.RefreshToken, TokenTypeHints.RefreshToken, cancellationToken);

        // The provider answered that the token is gone, so redeeming it must now fail. This is the assertion
        // the unit suite cannot make: a stub returns 200 because it was told to, while here the 200 has to
        // have been earned by the server actually forgetting the grant.
        await Assert.ThrowsAsync<TokenRequestException>(
            () => client.GetRequiredService<IOidcClient>()
                .RefreshAsync(signIn.RefreshToken, cancellationToken));
    }

    /// <summary>
    /// The logout address the client builds is one the provider accepts, hint and all.
    /// </summary>
    /// <remarks>
    /// What is being checked is that the request itself is well formed: the endpoint address came from
    /// discovery, the ID Token hint is one this provider issued, and the client identifier beside it matches
    /// the one the hint was issued to - which section 2 makes the provider verify.
    /// </remarks>
    [Fact]
    public async Task TheProviderAcceptsTheLogoutRequest()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var client = fixture.CreateOidcClient();

        var signIn = await SignInAsync(client, cancellationToken);

        var logoutUri = await client.GetRequiredService<IOidcClient>()
            .CreateEndSessionRequestAsync(
                signIn.EncodedIdentityToken, cancellationToken: cancellationToken);

        using var browser = fixture.CreateBrowser();
        using var response = await browser.GetAsync(logoutUri, cancellationToken);

        Assert.NotEqual(HttpStatusCode.BadRequest, response.StatusCode);
    }

    /// <summary>
    /// Signs in through the facade, for the tests whose subject is what happens next.
    /// </summary>
    /// <remarks>
    /// Through <see cref="IOidcClient"/> rather than the parts, so that the composition a host actually
    /// calls is the one every test below runs on. The parts have their own case above.
    /// </remarks>
    private async Task<CompletedSignIn> SignInAsync(
        IServiceProvider client, CancellationToken cancellationToken)
    {
        var request = await client.GetRequiredService<IOidcClient>()
            .CreateAuthorizationRequestAsync(
                new Uri(ClientAgainstServerFixture.ReturnPath, UriKind.Relative), cancellationToken: cancellationToken);

        var callback = await FollowAsync(request.RequestUri, cancellationToken);

        return await client.GetRequiredService<IOidcClient>()
            .HandleCallbackAsync(callback, cancellationToken);
    }

    /// <summary>
    /// The provider states the login state, and the client carries it to the host together with the frame
    /// to poll.
    /// </summary>
    /// <remarks>
    /// A unit test can only show that a value put in comes out. Here the value is one this provider
    /// calculated, under the parameter name it chose, and the frame address is the one it published.
    /// </remarks>
    [Fact]
    public async Task TheLoginStateAndTheFrameToPollReachTheHost()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var client = fixture.CreateOidcClient();

        var signIn = await SignInAsync(client, cancellationToken);

        Assert.False(string.IsNullOrEmpty(signIn.SessionState));

        var check = await client.GetRequiredService<IOidcClient>()
            .CreateSessionCheckAsync(signIn.SessionState, cancellationToken);

        Assert.NotNull(check);
        Assert.StartsWith(
            ClientAgainstServerFixture.Issuer, check.CheckSessionIframe, StringComparison.Ordinal);
        Assert.Equal($"{ClientAgainstServerFixture.ClientId} {signIn.SessionState}", check.Message);
    }

    /// <summary>
    /// The provider answers a silent re-check from the session it already has, without asking the user
    /// anything.
    /// </summary>
    /// <remarks>
    /// This is the request OpenID Connect Session Management 1.0 section 2 has a client send when its
    /// watching frame reports a change. A unit test can show the parameter is on the wire; only a real
    /// provider can say whether it is answered rather than refused.
    /// </remarks>
    [Fact]
    public async Task ASilentRequestIsAnsweredFromTheExistingSession()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var client = fixture.CreateOidcClient();

        var request = await client.GetRequiredService<IOidcClient>()
            .CreateAuthorizationRequestAsync(
                new Uri(ClientAgainstServerFixture.ReturnPath, UriKind.Relative), new AuthorizationRequestParameters { Prompt = [Prompts.None] }, cancellationToken);

        Assert.Contains("prompt=none", request.RequestUri.Query, StringComparison.Ordinal);

        var callback = await FollowAsync(request.RequestUri, cancellationToken);

        // Answered, not refused: no login_required, and a code to redeem.
        Assert.False(callback.ContainsKey("error"), $"the provider refused: {Describe(callback)}");

        var signIn = await client.GetRequiredService<IOidcClient>()
            .HandleCallbackAsync(callback, cancellationToken);

        Assert.Equal(Subject, signIn.Principal.Identity?.Name);
    }

    private static string Describe(IReadOnlyDictionary<string, IReadOnlyList<string>> parameters)
        => string.Join(", ", parameters.Select(entry => $"{entry.Key}={string.Join('|', entry.Value)}"));
}
