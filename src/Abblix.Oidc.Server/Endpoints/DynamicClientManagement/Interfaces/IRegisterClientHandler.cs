// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

/// <summary>
/// Handles <c>POST</c> requests to the registration endpoint per RFC 7591 section 3 and the
/// OpenID Connect Dynamic Client Registration 1.0 specification, validating supplied
/// metadata and provisioning a new client.
/// </summary>
public interface IRegisterClientHandler
{
    /// <summary>
    /// Validates the supplied client metadata and, on success, creates the client record,
    /// generates credentials, and issues the registration access token used for later
    /// management operations (RFC 7592).
    /// </summary>
    /// <param name="clientRegistrationRequest">The client metadata payload as defined in
    /// RFC 7591 section 2 and OIDC Dynamic Client Registration 1.0.</param>
    /// <returns>
    /// A successful response per RFC 7591 section 3.2.1 (containing <c>client_id</c>,
    /// <c>client_secret</c>, <c>registration_access_token</c>, etc.) or an error per section 3.2.2.
    /// </returns>
    Task<Result<ClientRegistrationSuccessResponse, OidcError>> HandleAsync(Model.ClientRegistrationRequest clientRegistrationRequest);
}
