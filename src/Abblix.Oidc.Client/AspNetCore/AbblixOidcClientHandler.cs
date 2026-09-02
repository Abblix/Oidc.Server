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

using System.Globalization;
using System.Text.Encodings.Web;
using Abblix.Oidc.Client.Features.Authorization.Context;
using Abblix.Oidc.Client.Features.Authorization.Responses;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Client.AspNetCore;

/// <summary>
/// Signs users in through an OpenID Provider, so that the rest of the application sees an ordinary
/// authenticated user.
/// </summary>
/// <remarks>
/// A remote handler rather than one that authenticates every request: the login happens once, at the
/// callback, and the resulting principal is handed to the sign-in scheme - a cookie, normally - which is
/// what every later request reads. That is the shape hosts already know from the framework's own OpenID
/// Connect handler, and it is the reason this one carries no session of its own.
/// </remarks>
/// <param name="options">Where the callback lands and where the signed-in user is kept.</param>
/// <param name="logger">The logging factory the base handler needs.</param>
/// <param name="encoder">The URL encoder the base handler needs.</param>
/// <param name="oidcClient">The client this handler is a thin layer over.</param>
public sealed class AbblixOidcClientHandler(
    IOptionsMonitor<AbblixOidcClientOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    IOidcClient oidcClient) : RemoteAuthenticationHandler<AbblixOidcClientOptions>(options, logger, encoder)
{
    /// <summary>
    /// Where the login state is kept among the session's own properties.
    /// </summary>
    /// <remarks>
    /// A host reads it from the authenticated session to render the watching frame. Named rather than
    /// left to a string literal, because the reader is in the host and the writer is here.
    /// </remarks>
    public const string SessionStateItemKey = "abblix.oidc.session_state";

    /// <summary>
    /// The names the session's tokens are stored under.
    /// </summary>
    /// <remarks>
    /// Named for the reason the session-state key is: the writer is here and the reader is in the host, or
    /// in the session-backed token source. They are the names the framework's own OpenID Connect handler
    /// uses, so a host that swaps one handler for the other reads the same session.
    /// </remarks>
    public const string IdentityTokenName = "id_token";

    /// <inheritdoc cref="IdentityTokenName"/>
    public const string AccessTokenName = "access_token";

    /// <inheritdoc cref="IdentityTokenName"/>
    public const string RefreshTokenName = "refresh_token";

    /// <inheritdoc cref="IdentityTokenName"/>
    public const string TokenTypeName = "token_type";

    /// <summary>
    /// When the access token stops being usable, in round-trip format.
    /// </summary>
    /// <remarks>
    /// Deliberately not the ticket's own <c>ExpiresUtc</c>. That one governs the session, and a host is free
    /// to set a sliding expiration or a longer window on it; conflating the two makes a token look alive
    /// because the session is.
    /// </remarks>
    public const string AccessTokenExpiresAtName = "expires_at";

    /// <summary>
    /// Sends the user to the provider to sign in.
    /// </summary>
    /// <remarks>
    /// Where the user was heading is taken from the challenge and handed to the client, which stores it with
    /// the rest of the login state and checks it is local. The base class's correlation cookie is not used:
    /// the client already binds a callback to the login that started it through the state it stored, and
    /// where that state lives - a cookie, a distributed cache - is the host's choice rather than something
    /// this handler should decide by adding a cookie of its own.
    /// </remarks>
    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        var request = await oidcClient.CreateAuthorizationRequestAsync(
            ReturnUri(properties), cancellationToken: Context.RequestAborted);

        Response.Redirect(request.RequestUri.OriginalString);
    }

    /// <summary>
    /// Finishes the login the callback belongs to.
    /// </summary>
    /// <remarks>
    /// Every failure comes back as <see cref="HandleRequestResult.Fail(string)"/> rather than as an
    /// exception escaping into the pipeline, which is what the framework expects of a remote handler and
    /// what lets a host render its own page for a login that did not work out.
    /// </remarks>
    protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
    {
        CompletedSignIn signIn;
        try
        {
            signIn = await oidcClient.HandleCallbackAsync(
                AuthorizationResponseHandlerExtensions.ReadCallback(Request), Context.RequestAborted);
        }
        catch (Exception exception) when (
            exception is AuthorizationResponseException
                or AuthorizationStateException
                or Features.IdentityTokens.IdentityTokenValidationException
                or Features.Tokens.TokenRequestException)
        {
            return HandleRequestResult.Fail(exception);
        }

        var properties = new AuthenticationProperties
        {
            // Where the user was heading when the login started. The base class redirects here once the
            // principal has been handed to the sign-in scheme.
            RedirectUri = signIn.ReturnUri,
            ExpiresUtc = signIn.ExpiresIn is { } lifetime ? TimeProvider.GetUtcNow() + lifetime : null,
        };

        // Kept whether or not tokens are saved, because it is not a credential: OpenID Connect Session
        // Management 1.0 section 2 calls it opaque to the client, and a page watching the session needs it
        // on every later request, not only at the moment of signing in.
        if (signIn.SessionState is { } sessionState)
            properties.Items[SessionStateItemKey] = sessionState;

        if (Options.SaveTokens)
            StoreTokens(properties, signIn);

        return HandleRequestResult.Success(
            new AuthenticationTicket(signIn.Principal, properties, Scheme.Name));
    }

    /// <summary>
    /// Keeps the tokens with the session, for a host that asked for them.
    /// </summary>
    /// <remarks>
    /// Off unless the host says otherwise, because they are bearer credentials and where the session is kept
    /// decides who can read them. The ID Token is kept verbatim: logging out sends it as <c>id_token_hint</c>
    /// and a re-serialized one would not verify.
    /// </remarks>
    private void StoreTokens(AuthenticationProperties properties, CompletedSignIn signIn)
    {
        var tokens = new List<AuthenticationToken>
        {
            new() { Name = IdentityTokenName, Value = signIn.EncodedIdentityToken },
        };

        if (signIn.AccessToken is { } accessToken)
            tokens.Add(new AuthenticationToken { Name = AccessTokenName, Value = accessToken });

        if (signIn.RefreshToken is { } refreshToken)
            tokens.Add(new AuthenticationToken { Name = RefreshTokenName, Value = refreshToken });

        // The type says how the token is presented (RFC 6749 section 5.1), so it travels with it. Kept
        // alongside rather than assumed, because assuming it here would decide for every future scheme.
        if (signIn.TokenType is { } tokenType)
            tokens.Add(new AuthenticationToken { Name = TokenTypeName, Value = tokenType });

        // An absolute instant rather than a duration, because a duration is only meaningful next to the
        // moment it was measured from, and that moment is gone by the time anything reads this.
        if (signIn.ExpiresIn is { } lifetime)
        {
            tokens.Add(new AuthenticationToken
            {
                Name = AccessTokenExpiresAtName,
                Value = (TimeProvider.GetUtcNow() + lifetime).ToString("o", CultureInfo.InvariantCulture),
            });
        }

        properties.StoreTokens(tokens);
    }

    /// <summary>
    /// Where to put the user once the login finishes.
    /// </summary>
    /// <remarks>
    /// The challenge usually carries it; a challenge raised by an authorization check on the current page
    /// does not, and then the current page is the right answer.
    /// </remarks>
    private Uri ReturnUri(AuthenticationProperties properties)
        => new(
            properties.RedirectUri
            ?? Request.PathBase + Request.Path + Request.QueryString,
            UriKind.Relative);

}
