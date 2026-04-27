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
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

/// <summary>
/// Validates a request against the client configuration endpoint (RFC 7592 §2-§4).
/// Confirms that the bearer registration access token authorizes the operation on the
/// referenced <c>client_id</c> and that the client still exists.
/// </summary>
public interface IClientRequestValidator
{
    /// <summary>
    /// Validates the request, returning the resolved <see cref="ValidClientRequest"/> on success
    /// or an <see cref="OidcError"/> describing the rejection.
    /// </summary>
    /// <param name="request">The client management request to validate.</param>
    Task<Result<ValidClientRequest, OidcError>> ValidateAsync(ClientRequest request);
}
