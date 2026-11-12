// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// The values a client's authentication assertions may name as their audience, the <c>aud</c> claim of a
/// <c>private_key_jwt</c> or <c>client_secret_jwt</c> assertion.
/// </summary>
/// <remarks>
/// RFC 10070 section 4 makes the authorization server "reject any JWT that does not contain its issuer identifier as
/// its sole audience value", so <see cref="Issuer"/> alone is the value every client is held to: an unset set reads as
/// it, and a configured set without it is refused at startup. <see cref="TokenEndpoint"/> and
/// <see cref="AllowArray"/> are the transition section 6 of the same RFC expects, granted by the host to a client that
/// cannot change yet.
/// </remarks>
[Flags]
public enum ClientAssertionAudiences
{
    /// <summary>
    /// The issuer identifier, as a string, the form OpenID Connect Core 1.0 draft 36 section 9 requires of a client:
    /// "passed as a string, and not a single-element array".
    /// </summary>
    Issuer = 1 << 0,

    /// <summary>
    /// The token endpoint URL, as a string, as OpenID Connect Core 1.0 section 9 recommends: the path the
    /// endpoint is served at on the issuer identifier's scheme, host and port, written either as the issuer identifier
    /// writes them or normalized, never the host a request names, and never the pushed authorization request endpoint
    /// URL.
    /// </summary>
    /// <remarks>
    /// Granting it reopens, for this client, the audience confusion RFC 10070 closes, so it belongs to a client that
    /// cannot yet be changed and is removed when it is. A client held to FAPI 2.0 cannot have it: section 5.3.2.1 has
    /// the server "only accept its issuer identifier value ... as a string in the aud claim received in client
    /// authentication assertions".
    /// </remarks>
    TokenEndpoint = 1 << 1,

    /// <summary>
    /// An array of strings of any length, holding the issuer identifier, or the token endpoint URL for a client granted
    /// <see cref="TokenEndpoint"/>, beside other values, as RFC 7523 section 3 has it: the claim contains "a value that
    /// identifies the authorization server as an intended audience".
    /// </summary>
    /// <remarks>
    /// This is the form RFC 10070 section 4 closes, an assertion naming several servers that each of them accepts, so
    /// it belongs to a client that cannot yet be changed and is removed when it is. A client held to FAPI 2.0 cannot
    /// have it, for the reason <see cref="TokenEndpoint"/> gives.
    /// </remarks>
    AllowArray = 1 << 2,
}
