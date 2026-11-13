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
/// The lifetime a client's security profile allows its request objects, as
/// <see cref="SecurityProfileRequirements.MaxRequestObjectLifetime"/> states it.
/// </summary>
internal static class RequestObjectLifetime
{
    /// <summary>
    /// Why the request object's lifetime falls outside what the profile allows, or null when it does not or the
    /// profile bounds no lifetime.
    /// </summary>
    /// <remarks>
    /// The timestamps are read through <see cref="JsonWebTokenPayload.TryReadTimestamps"/> rather than the
    /// accessors: the validator that passed the object is the host's to replace, and one that never read these
    /// claims must not turn an unreadable one into an exception here.
    /// </remarks>
    /// <param name="requirements">The controls the client is held to.</param>
    /// <param name="payload">The request object's claims.</param>
    /// <param name="now">The instant the request object is judged at.</param>
    public static string? WhyRefused(
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
}
