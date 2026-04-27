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
