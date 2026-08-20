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
/// Handles <c>DELETE</c> requests to the client configuration endpoint per RFC 7592 §2.3,
/// deregistering an existing client after verifying its registration access token.
/// A successful deletion invalidates the client's <c>client_id</c>, <c>client_secret</c>,
/// the registration access token, and any outstanding grants and tokens.
/// </summary>
public interface IRemoveClientHandler
{
    /// <summary>
    /// Validates the request, then removes the addressed client. The HTTP layer is expected to
    /// translate the success result into <c>204 No Content</c> per RFC 7592 §2.3.
    /// </summary>
    /// <param name="clientRequest">The incoming request including the registration access token
    /// and target <c>client_id</c>.</param>
    Task<Result<RemoveClientSuccessfulResponse, OidcError>> HandleAsync(ClientRequest clientRequest);
}
