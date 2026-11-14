// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.Features.RequestObject;

/// <summary>
/// What a client's security profile demands of the claims of its request objects beyond RFC 9101: the lifetime
/// <see cref="SecurityProfileRequirements.MaxRequestObjectLifetime"/> bounds and the audience
/// <see cref="SecurityProfileRequirements.RequireIssuerAudienceInRequestObject"/> requires.
/// </summary>
internal static class RequestObjectProfileRules
{
    /// <summary>
    /// Why the request object's claims fall outside what the profile allows, or null when they do not.
    /// </summary>
    /// <param name="requirements">The controls the client is held to.</param>
    /// <param name="payload">The request object's claims.</param>
    /// <param name="issuer">The issuer identifier of the tenant the request object reached.</param>
    /// <param name="now">The instant the request object is judged at.</param>
    public static string? WhyRefused(
        SecurityProfileRequirements requirements,
        JsonWebTokenPayload payload,
        Uri issuer,
        DateTimeOffset now)
        => WhyLifetimeRefused(requirements, payload, now) ?? WhyAudienceRefused(requirements, payload, issuer);

    /// <summary>
    /// Why the request object's lifetime falls outside what the profile allows, or null when it does not or the
    /// profile bounds no lifetime.
    /// </summary>
    /// <remarks>
    /// The timestamps are read through <see cref="JsonWebTokenPayload.TryReadTimestamps"/> rather than the
    /// accessors: the validator that passed the object is the host's to replace, and one that never read these
    /// claims must not turn an unreadable one into an exception here.
    /// </remarks>
    private static string? WhyLifetimeRefused(
        SecurityProfileRequirements requirements,
        JsonWebTokenPayload payload,
        DateTimeOffset now)
    {
        if (requirements.MaxRequestObjectLifetime is not { } bound)
            return null;

        if (!payload.TryReadTimestamps(out var notBefore, out var expiresAt, out _, out var whyUnreadable))
            return whyUnreadable;

        if (notBefore is not { } nbf)
            return "The request object must carry an nbf claim";

        if (expiresAt is not { } exp)
            return "The request object must carry an exp claim";

        if (exp - nbf > bound)
            return "The request object's exp lies too far after its nbf";

        if (nbf < now - bound)
            return "The request object's nbf lies too far in the past";

        return null;
    }

    /// <summary>
    /// Why the request object's audience is not one the profile allows, or null when it is or the profile requires
    /// none.
    /// </summary>
    /// <remarks>
    /// FAPI 1.0 Part 2 section 5.2.2: the aud claim is "to be, or to be an array containing, the OP's Issuer
    /// Identifier URL". The validator that passed the object accepted an absent aud and one naming only the endpoint
    /// it was sent to, as RFC 9101 alone allows. Compared as the issuer is written, the way that validator compares
    /// it.
    /// </remarks>
    private static string? WhyAudienceRefused(
        SecurityProfileRequirements requirements,
        JsonWebTokenPayload payload,
        Uri issuer)
    {
        if (!requirements.RequireIssuerAudienceInRequestObject)
            return null;

        return payload.Audiences.Contains(issuer.OriginalString, StringComparer.Ordinal)
            ? null
            : "The request object must name the issuer identifier as its audience";
    }
}
