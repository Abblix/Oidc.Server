// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
// 
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
// 
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
// 
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
// 
// For full licensing terms, please visit:
// 
// https://oidc.abblix.com/license
// 
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Abblix.Oidc.Server.Common;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

/// <summary>
/// Handles <c>POST</c> requests to the registration endpoint per RFC 7591 §3 and the
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
    /// RFC 7591 §2 and OIDC Dynamic Client Registration 1.0.</param>
    /// <returns>
    /// A successful response per RFC 7591 §3.2.1 (containing <c>client_id</c>,
    /// <c>client_secret</c>, <c>registration_access_token</c>, etc.) or an error per §3.2.2.
    /// </returns>
    Task<Result<ClientRegistrationSuccessResponse, OidcError>> HandleAsync(Model.ClientRegistrationRequest clientRegistrationRequest);
}
