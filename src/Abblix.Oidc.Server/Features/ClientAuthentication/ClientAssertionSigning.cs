// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Reads how a client assertion is protected from its JOSE header alone, verifying nothing, so that each of
/// client_secret_jwt and private_key_jwt claims the assertions signed with its own algorithms and passes over the rest
/// unlogged.
/// </summary>
internal static class ClientAssertionSigning
{
    /// <summary>
    /// The dot-separated parts of a compact JWE (RFC 7516 section 7.1).
    /// </summary>
    private const int JweCompactParts = 5;

    /// <summary>
    /// Whether <paramref name="assertion"/> is a compact JWE, which both methods read: its header names how the content
    /// key is managed rather than how the assertion inside is signed.
    /// </summary>
    /// <param name="assertion">The client assertion as presented.</param>
    public static bool IsEncrypted(string assertion) => assertion.Split('.').Length == JweCompactParts;

    /// <summary>
    /// The algorithm the header of <paramref name="assertion"/> names, or null where it names none or its first part is
    /// not base64url of a JSON object. The payload is not read: it says nothing of how the assertion is signed.
    /// </summary>
    /// <param name="assertion">The client assertion as presented.</param>
    public static string? AlgorithmOf(string assertion)
    {
        byte[] header;
        try
        {
            header = JoseBase64Url.Decode(assertion.Split('.')[0]);
        }
        catch (FormatException)
        {
            return null;
        }

        return JoseJson.TryParseObject(header, out var json) ? new JsonWebTokenHeader(json).Algorithm : null;
    }
}
