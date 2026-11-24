// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt.ReplayPrevention;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ReplayPrevention;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Reserves the jti of a client assertion, so the assertion cannot be presented a second time, for no longer than the
/// deployment lets an assertion be valid.
/// </summary>
/// <param name="replayCache">Records the reserved identifiers and atomically refuses one reserved before.</param>
/// <param name="options">Where the ceiling is read from, each time, so a reload takes effect.</param>
/// <param name="clock">The time the ceiling is measured from.</param>
internal sealed class ClientAssertionReplay(
    IReplayCache replayCache, IOptionsMonitor<OidcOptions> options, TimeProvider clock)
{
    /// <summary>
    /// Why an assertion expiring at <paramref name="expiresAt"/>, issued at <paramref name="issuedAt"/>, is valid for
    /// longer than <see cref="OidcOptions.ClientAssertionMaxLifetime"/>, or null when it is not.
    /// </summary>
    /// <remarks>
    /// RFC 7523 section 3 item 4: "the authorization server may reject JWTs with an "exp" claim value that is
    /// unreasonably far in the future", which the bound on exp past the current time measures. Item 6: "the
    /// authorization server may reject JWTs with an "iat" claim value that is unreasonably far in the past"; for an
    /// assertion still valid, an iat far in the past shows as exp far past iat, so both bounds measure the one
    /// lifetime the setting names. Item 7 has the server keep the used jti values "for the length of time for which
    /// the JWT would be considered valid based on the applicable "exp" instant", so the ceiling also bounds how long a
    /// reserved jti is held, which is why the caller asks this before <see cref="TryReserveAsync"/>: a refused
    /// assertion reserves nothing. Measured from now, the bound allows the forward clock skew the client's timestamps are
    /// judged with, so a client whose clock runs ahead within it may mint an assertion of exactly the ceiling.
    /// </remarks>
    /// <param name="expiresAt">The assertion's exp.</param>
    /// <param name="issuedAt">The assertion's iat, when it carries one.</param>
    /// <param name="forwardSkew">How far ahead of this server's clock the client's timestamps may be dated.</param>
    public string? WhyTooLong(DateTimeOffset expiresAt, DateTimeOffset? issuedAt, TimeSpan forwardSkew)
    {
        var ceiling = options.CurrentValue.ClientAssertionMaxLifetime;

        if (expiresAt - clock.GetUtcNow() > ceiling + forwardSkew)
            return $"it expires more than {ceiling} from now";

        if (expiresAt - issuedAt > ceiling)
            return $"it expires more than {ceiling} after it was issued";

        return null;
    }

    /// <summary>
    /// Reserves <paramref name="tokenId"/> for <paramref name="clientId"/> until <paramref name="expiresAt"/>,
    /// answering whether it was not reserved before.
    /// </summary>
    /// <remarks>
    /// Single atomic reserve-and-check: one call avoids the read-then-write race a separate status check and mark step
    /// would leave between two concurrent presenters of the same assertion. Client authentication is handed no
    /// cancellation of the request, and the issuer's Released is not one: it lets memory go after a request under way
    /// finishes.
    /// </remarks>
    /// <param name="clientId">The client the assertion authenticates, which issued it.</param>
    /// <param name="tokenId">The assertion's jti.</param>
    /// <param name="expiresAt">The assertion's expiry, which bounds the reservation.</param>
    public Task<bool> TryReserveAsync(string clientId, string tokenId, DateTimeOffset expiresAt)
        => replayCache.TryReserveAsync(
            SingleUseTokenKey.ClientAssertion(clientId, tokenId), expiresAt, CancellationToken.None);
}
