// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net.Http.Headers;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

/// <summary>
/// Validates the registration access token presented on calls to the client configuration
/// endpoint per RFC 7592 §3. Verifies the bearer token from the <c>Authorization</c> header
/// is bound to the requested <c>client_id</c>.
/// </summary>
public interface IRegistrationAccessTokenValidator
{
    /// <summary>
    /// Validates the bearer token, ensuring it is well-formed, of the expected type, and
    /// authorized to manage the specified client.
    /// </summary>
    /// <param name="header">The HTTP <c>Authorization</c> header carrying the bearer token.</param>
    /// <param name="clientId">The <c>client_id</c> targeted by the management request.</param>
    /// <param name="expectedTokenId">
    /// The jti the token must carry to be accepted - the value stored on the client when its
    /// current registration access token was issued. When <c>null</c> the binding is not enforced
    /// (statically configured client, or a record predating the stored id) and only signature,
    /// type and audience are checked.
    /// </param>
    /// <returns>
    /// <c>null</c> when the token is valid for the client; otherwise a human-readable description
    /// of the validation failure.
    /// </returns>
    Task<string?> ValidateAsync(AuthenticationHeaderValue? header, string clientId, string? expectedTokenId);
}
