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
/// it, and a configured set without it is refused at startup. <see cref="TokenEndpoint"/>,
/// <see cref="BackChannelAuthenticationEndpoint"/> and <see cref="AllowArray"/> are the transition section 6 of the
/// same RFC expects, granted by the host to a client that cannot change yet.
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
    /// URL. For a tenant with a mutual-TLS address, the same path on that address, in either spelling, is accepted too:
    /// it is the endpoint's alias, which RFC 8705 section 5 has a client doing mutual TLS use in preference to the
    /// ordinary endpoint.
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

    /// <summary>
    /// The backchannel authentication endpoint URL, as a string, which CIBA Core 1.0 section 7.1 has the server accept:
    /// "the OP MUST accept its Issuer Identifier, Token Endpoint URL, or Backchannel Authentication Endpoint URL as
    /// values that identify it as an intended audience". Spelled as <see cref="TokenEndpoint"/> is, on the issuer
    /// identifier's scheme, host and port and on the tenant's mutual-TLS address, and accepted wherever the client
    /// authenticates, as the token endpoint URL is.
    /// </summary>
    /// <remarks>
    /// RFC 10070 leaves CIBA unchanged but closes the same ambiguity for every assertion: "the authorization server MUST
    /// reject any JWT that does not contain its issuer identifier as its sole audience value", since "other endpoint
    /// values of the metadata cannot be directly validated and, if used as the audience when sent to a different
    /// endpoint, can open an attack vector". So it is granted by the host to a CIBA client that writes this URL, and
    /// removed when the client is changed. A client held to FAPI 2.0 cannot have it, for the reason
    /// <see cref="TokenEndpoint"/> gives.
    /// </remarks>
    BackChannelAuthenticationEndpoint = 1 << 3,
}
