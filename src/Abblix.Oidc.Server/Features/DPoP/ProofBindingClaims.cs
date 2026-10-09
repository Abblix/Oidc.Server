// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Abblix.Jwt;

namespace Abblix.Oidc.Server.Features.DPoP;

/// <summary>
/// Checks the claims that bind a DPoP proof to the request it accompanies (RFC 9449 section 4.3): the method, the
/// target URI and, when an access token is presented, its hash.
/// </summary>
internal static class ProofBindingClaims
{
    /// <summary>
    /// Compares the proof's <c>htm</c> claim against the current request method
    /// byte-exact (RFC 9449 section 4.3).
    /// </summary>
    public static ProofError? HttpMethod(JsonWebTokenPayload payload, string httpMethod)
    {
        var actualHttpMethod = payload.DPoPHttpMethod;
        if (actualHttpMethod != httpMethod)
        {
            return new ProofError(
                ProofErrorReasons.HttpMethodMismatch,
                $"{IanaClaimTypes.Htm} '{actualHttpMethod ?? "<missing>"}' does not match request method '{httpMethod}'.");
        }

        return null;
    }

    /// <summary>
    /// Compares the proof's <c>htu</c> claim against the current request URI after
    /// RFC 3986 section 6.2 canonicalisation.
    /// </summary>
    public static ProofError? HttpUri(JsonWebTokenPayload payload, Uri requestUri)
    {
        var httpUri = payload.DPoPHttpUri;
        if (httpUri is null)
        {
            return new ProofError(
                ProofErrorReasons.HttpUriMissing,
                $"{IanaClaimTypes.Htu} claim is required.");
        }

        if (!Uri.TryCreate(httpUri, UriKind.Absolute, out var uri))
        {
            return new ProofError(
                ProofErrorReasons.HttpUriInvalid,
                $"{IanaClaimTypes.Htu} is not a valid absolute URI.");
        }

        if (uri.Normalize() != requestUri.Normalize())
        {
            return new ProofError(
                ProofErrorReasons.HttpUriMismatch,
                $"{IanaClaimTypes.Htu} does not match the request URI after canonicalisation.");
        }

        return null;
    }

    /// <summary>
    /// When the proof accompanies an access token, verifies the <c>ath</c> claim equals
    /// <c>Base64Url(SHA-256(access_token))</c> per RFC 9449 section 4.2.
    /// </summary>
    public static ProofError? AccessToken(JsonWebTokenPayload payload, string? accessToken)
    {
        if (accessToken is null)
            return null;

        var accessTokenHash = payload.DPoPAccessTokenHash;
        if (accessTokenHash is null)
        {
            return new ProofError(
                ProofErrorReasons.AccessTokenHashMissing,
                $"{IanaClaimTypes.Ath} claim is required when an access token is presented.");
        }

        var expected = Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken)));
        if (accessTokenHash != expected)
        {
            return new ProofError(
                ProofErrorReasons.AccessTokenHashMismatch,
                $"{IanaClaimTypes.Ath} does not match the access-token hash.");
        }

        return null;
    }
}
