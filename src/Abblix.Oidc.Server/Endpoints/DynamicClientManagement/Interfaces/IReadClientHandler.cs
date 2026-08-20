// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

/// <summary>
/// Handles <c>GET</c> requests to the client configuration endpoint per RFC 7592 §2.1,
/// returning the registered metadata of the authenticated client.
/// </summary>
public interface IReadClientHandler
{
    /// <summary>
    /// Validates the registration access token, then retrieves the current configuration of
    /// the addressed client. Returns either the client's metadata or an OIDC error suitable
    /// for the response body.
    /// </summary>
    /// <param name="clientRequest">The incoming request including the registration access token
    /// and target <c>client_id</c>.</param>
    Task<Result<ReadClientSuccessfulResponse, OidcError>> HandleAsync(ClientRequest clientRequest);
}
