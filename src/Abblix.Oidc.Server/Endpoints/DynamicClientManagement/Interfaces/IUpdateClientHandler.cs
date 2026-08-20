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
/// Defines a contract for handling requests to update client configurations, as part of client management in OAuth 2.0
/// and OpenID Connect frameworks per RFC 7592 Section 2.2.
/// </summary>
public interface IUpdateClientHandler
{
    /// <summary>
    /// Asynchronously handles a request to update a client's configuration details.
    /// </summary>
    /// <param name="request">The update request containing the client authentication and updated metadata.</param>
    /// <returns>A task that returns the updated client's configuration details or an error response.</returns>
    /// <remarks>
    /// This method processes the incoming request to update a client's configuration per RFC 7592.
    /// It validates the request to ensure proper authentication via registration_access_token,
    /// validates the updated metadata, and updates the client configuration.
    /// The response includes all client metadata with potentially updated registration_access_token.
    /// </remarks>
    Task<Result<ReadClientSuccessfulResponse, OidcError>> HandleAsync(UpdateClientRequest request);
}
