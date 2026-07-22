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
using Abblix.Oidc.Client.Common.Constants;
using Abblix.Oidc.Client.Features.ProtectedResources;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Client.AspNetCore;

/// <summary>
/// Takes the access token from the session of whoever is making the current request.
/// </summary>
/// <remarks>
/// The ready-made answer, and the one an ordinary web application wants: the user signed in, the handler
/// kept their tokens with the session, and a call to an API on their behalf carries the token they were
/// issued.
/// It is a singleton and holds nothing. The current request is reached through
/// <see cref="IHttpContextAccessor"/>, which is ambient and flows into a pooled message handler where a
/// scope does not - and which is null in a background job, where this source is the wrong one and says so.
/// One session holds one token, so a host calling two APIs gets the same token at both. If those APIs need
/// different audiences, the fix is a source of the host's own; that is what the seam is for.
/// </remarks>
/// <remarks>
/// One obligation here is the host's and cannot be met from this class, so it is written down rather than
/// assumed. RFC 6750 section 5.3: "Implementations MUST NOT store bearer tokens within cookies that can be
/// sent in the clear (which is the default transmission mode for cookies)." Reading the token out of a
/// cookie-backed session is exactly that arrangement, and what satisfies the rule is the cookie's own
/// policy - <c>CookieSecurePolicy.Always</c> on the sign-in scheme - plus forwarded headers where TLS is
/// terminated ahead of the application.
/// This source does not refuse to answer on a plain-HTTP request, and the reason is worth stating because
/// the opposite looks tempting. The MUST in the same section is scoped to the client "making requests with
/// bearer tokens", which is the outgoing side and is enforced where the token is sent. Refusing here would
/// not undo a cookie that already travelled in the clear, and it would break every deployment behind a
/// TLS-terminating proxy whose forwarded headers are not yet configured - failing at the wrong end, after
/// the harm, for a setting that lives elsewhere.
/// </remarks>
/// <param name="httpContextAccessor">Reaches the request being served, when there is one.</param>
/// <param name="options">Which scheme holds the session, and how much clock margin to leave.</param>
/// <param name="timeProvider">Reads the current time for the expiry comparison.</param>
internal sealed class SessionAccessTokenSource(
    IHttpContextAccessor httpContextAccessor,
    IOptions<SessionAccessTokenOptions> options,
    TimeProvider timeProvider) : IAccessTokenSource
{
    /// <inheritdoc />
    public async Task<AccessToken> GetTokenAsync(
        AccessTokenRequest request, CancellationToken cancellationToken = default)
    {
        var settings = options.Value;

        if (httpContextAccessor.HttpContext is not { } context)
        {
            throw new AccessTokenUnavailableException(
                AccessTokenUnavailableReason.NoAmbientSession,
                "There is no current HTTP request, so there is no signed-in user whose token could be "
                + "presented. This source reads the session of the request being served; a background job "
                + "supplies its own with AddAccessTokenSource<T>().");
        }

        // Authenticate and read the tokens as two steps rather than through GetTokenAsync, which is those
        // two collapsed. Collapsed, "not signed in" and "signed in but SaveTokens is off" both come back as
        // null, and those are the two situations an operator most needs told apart.
        var result = await context.AuthenticateAsync(settings.AuthenticationScheme);

        if (!result.Succeeded || result.Properties is not { } properties)
        {
            throw new AccessTokenUnavailableException(
                AccessTokenUnavailableReason.NoAmbientSession,
                $"The current request carries no authenticated session, so there is no token to present to "
                + $"'{request.Resource}'.");
        }

        var value = properties.GetTokenValue(AbblixOidcClientHandler.AccessTokenName);

        if (string.IsNullOrEmpty(value))
        {
            throw new AccessTokenUnavailableException(
                AccessTokenUnavailableReason.TokensNotStored,
                "The session holds no access token. Set SaveTokens on the OIDC scheme, which is off by "
                + "default because tokens are bearer credentials and where the session is kept decides who "
                + "can read them.");
        }

        RequireUnexpired(properties, settings, request);

        // The type the provider stated when it issued the token (RFC 6749 section 5.1). Absent only for a
        // session written before this client kept it, in which case Bearer is the only thing it can have
        // been: this client never asks for a sender-constrained token.
        var scheme = properties.GetTokenValue(AbblixOidcClientHandler.TokenTypeName);

        return new AccessToken(value, string.IsNullOrEmpty(scheme) ? TokenTypes.Bearer : scheme);
    }

    /// <summary>
    /// Refuses a token whose stated expiry has passed.
    /// </summary>
    /// <remarks>
    /// Refused here rather than sent and refused there. A resource server answers an expired token with a
    /// 401 that looks like every other 401, while this says which of the three things went wrong and costs
    /// no round trip.
    /// A session written without an expiry is not treated as expired: it is a session from a version that
    /// did not record one, and refusing it would log out every user across an upgrade.
    /// </remarks>
    private void RequireUnexpired(
        AuthenticationProperties properties,
        SessionAccessTokenOptions settings,
        AccessTokenRequest request)
    {
        var stated = properties.GetTokenValue(AbblixOidcClientHandler.AccessTokenExpiresAtName);

        if (string.IsNullOrEmpty(stated)
            || !DateTimeOffset.TryParse(
                stated,
                CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind,
                out var expiresAt))
        {
            return;
        }

        if (expiresAt - settings.ExpiryClockSkew <= timeProvider.GetUtcNow())
        {
            throw new AccessTokenUnavailableException(
                AccessTokenUnavailableReason.Expired,
                $"The access token in the session expired at {expiresAt:O}, so it is not presented to "
                + $"'{request.Resource}'. This client does not refresh on the host's behalf; a host that "
                + "wants it done supplies an IAccessTokenSource that does.");
        }
    }
}
