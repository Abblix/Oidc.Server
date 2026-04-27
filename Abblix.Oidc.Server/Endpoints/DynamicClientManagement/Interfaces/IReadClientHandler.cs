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
