// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Features.ResponseObject;

/// <summary>
/// Helpers over the <c>response_mode</c> value for JARM
/// (<see href="https://openid.net/specs/oauth-v2-jarm-final.html">JWT Secured Authorization Response Mode</see>).
/// </summary>
public static class ResponseModeExtensions
{
    /// <summary>
    /// Determines whether the given response mode is a JARM (JWT-secured) mode - one of
    /// <see cref="ResponseModes.QueryJwt"/>, <see cref="ResponseModes.FragmentJwt"/>,
    /// <see cref="ResponseModes.FormPostJwt"/> or <see cref="ResponseModes.Jwt"/>.
    /// </summary>
    public static bool IsJwtMode(this string responseMode) => responseMode is
        ResponseModes.QueryJwt or
        ResponseModes.FragmentJwt or
        ResponseModes.FormPostJwt or
        ResponseModes.Jwt;

    /// <summary>
    /// Resolves a JARM (JWT-secured) response mode to the plaintext delivery mode that carries the response JWT:
    /// <see cref="ResponseModes.QueryJwt"/>→<see cref="ResponseModes.Query"/>,
    /// <see cref="ResponseModes.FragmentJwt"/>→<see cref="ResponseModes.Fragment"/>,
    /// <see cref="ResponseModes.FormPostJwt"/>→<see cref="ResponseModes.FormPost"/>. The
    /// <see cref="ResponseModes.Jwt"/> shortcut resolves to <see cref="ResponseModes.Fragment"/> for token-bearing
    /// flows and <see cref="ResponseModes.Query"/> otherwise (JARM §2.3.4). A non-JWT mode is returned unchanged.
    /// </summary>
    /// <param name="responseMode">The requested response mode.</param>
    /// <param name="carriesTokens">Whether the response carries front-channel tokens (used for the
    /// <see cref="ResponseModes.Jwt"/> shortcut).</param>
    public static string ToDeliveryMode(this string responseMode, bool carriesTokens) => responseMode switch
    {
        ResponseModes.QueryJwt => ResponseModes.Query,
        ResponseModes.FragmentJwt => ResponseModes.Fragment,
        ResponseModes.FormPostJwt => ResponseModes.FormPost,
        ResponseModes.Jwt when carriesTokens => ResponseModes.Fragment,
        ResponseModes.Jwt => ResponseModes.Query,
        _ => responseMode,
    };
}
