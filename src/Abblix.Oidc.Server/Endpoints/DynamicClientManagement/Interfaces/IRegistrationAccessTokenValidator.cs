// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net.Http.Headers;
using Abblix.Oidc.Server.Common;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

/// <summary>
/// Validates the registration access token presented on calls to the client configuration
/// endpoint per RFC 7592 section 3. Verifies the bearer token from the <c>Authorization</c> header
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
    /// <returns>
    /// The jti of the token when it is valid for the client, which the caller matches against the one its
    /// registration holds; otherwise an <c>invalid_token</c> error describing the failure.
    /// </returns>
    Task<Result<string, OidcError>> ValidateAsync(AuthenticationHeaderValue? header, string clientId);
}
