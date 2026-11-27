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
using Abblix.Jwt.ReplayPrevention;

namespace Abblix.Oidc.Server.Features.ReplayPrevention;

/// <summary>
/// The value the server reserves in <see cref="IReplayCache"/> for the jti of one single-use token it accepts: a client
/// assertion, a JWT bearer grant assertion or a DPoP proof.
/// </summary>
/// <remarks>
/// The one composition for the jti of these three kinds of token, so the question "under which key is a jti reserved"
/// has one answer for each of them; a receiver of security event tokens composes its own. The kind keeps
/// the three apart, since one party may mint all three with the same identifier. The party that issued the token
/// scopes its identifier: RFC 7519 section 4.1.7 has a jti unique to its issuer, "if the application uses multiple
/// issuers, collisions MUST be prevented among values produced by different issuers as well", so two clients presenting
/// the same jti do not refuse each other. The jti is reserved as its SHA-256 digest, which RFC 9449 section 11.1 offers
/// against memory exhaustion ("store only a hash thereof") and which bounds the key whatever the token carries. The
/// kind and the digest hold no colon, so the issuer between them cannot make two compositions one. The tenant is not
/// written here: <c>TenantReplayCache</c> scopes every reservation to the tenant it is made at.
/// </remarks>
internal static class SingleUseTokenKey
{
    /// <summary>
    /// The value to reserve for the jti of a client authentication assertion (RFC 7523 section 2.2).
    /// </summary>
    /// <param name="clientId">The client that issued the assertion.</param>
    /// <param name="tokenId">The assertion's jti.</param>
    public static string ClientAssertion(string clientId, string tokenId) => Of("client-assertion", clientId, tokenId);

    /// <summary>
    /// The value to reserve for the jti of a JWT bearer authorization grant assertion (RFC 7523 section 2.1).
    /// </summary>
    /// <param name="issuer">The issuer of the assertion.</param>
    /// <param name="tokenId">The assertion's jti.</param>
    public static string JwtBearerGrant(string issuer, string tokenId) => Of("jwt-bearer-grant", issuer, tokenId);

    /// <summary>
    /// The value to reserve for the jti of a DPoP proof (RFC 9449 section 4.2), which names no issuer: the key that
    /// signs it, by its JWK thumbprint, is the party that minted it.
    /// </summary>
    /// <param name="keyThumbprint">The RFC 7638 thumbprint of the proof's key.</param>
    /// <param name="tokenId">The proof's jti.</param>
    public static string DPoPProof(string keyThumbprint, string tokenId) => Of("dpop-proof", keyThumbprint, tokenId);

    private static string Of(string kind, string issuer, string tokenId)
        => $"{kind}:{issuer}:{Base64Url.EncodeToString(SHA256.HashData(Encoding.UTF8.GetBytes(tokenId)))}";
}
