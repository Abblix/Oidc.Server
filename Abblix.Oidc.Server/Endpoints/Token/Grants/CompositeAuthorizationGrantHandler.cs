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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// A composite handler that coordinates multiple authorization grant handlers for processing OAuth 2.0 token requests.
/// This class allows for flexible and extensible handling of various grant types by delegating specific grant processing
/// tasks to individual handlers. It dynamically aggregates all available grant handlers, facilitating the addition
/// of new handlers without modifying the core authorization flow.
/// </summary>
/// <param name="grantHandlers">
/// A collection of grant handlers, each responsible for a specific set of grant types.</param>
public class CompositeAuthorizationGrantHandler(IEnumerable<IAuthorizationGrantHandler> grantHandlers): IAuthorizationGrantHandler
{
    private readonly Dictionary<string, IAuthorizationGrantHandler> _grantHandlers = new(
        from handler in grantHandlers
        from grantType in handler.GrantTypesSupported
        select new KeyValuePair<string, IAuthorizationGrantHandler>(grantType, handler),
        StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Provides a list of all the supported grant types across the registered grant handlers.
    /// This allows the composite handler to advertise the full set of supported grant types, which
    /// can be used for validation and discovery of capabilities by client applications.
    /// </summary>
    public IEnumerable<string> GrantTypesSupported => _grantHandlers.Keys;

    /// <summary>
    /// Processes a token request asynchronously by delegating the request to the appropriate handler based on
    /// the grant type. If a handler for the requested grant type is found, it delegates the request to that handler
    /// for processing. Otherwise, it returns an error indicating that the grant type is not supported.
    /// This method abstracts away the complexity of identifying and invoking the correct handler, simplifying the main
    /// authorization flow.
    /// </summary>
    /// <param name="request">
    /// The token request, which includes the grant type and relevant parameters for processing the request.</param>
    /// <param name="clientInfo">
    /// The client information used to validate and process the request, ensuring the request is authorized.</param>
    /// <returns>A task that resolves to the result of the authorization process.
    /// If successful, it contains the granted authorization;
    /// otherwise, it contains an error explaining why the authorization failed.</returns>
    public async Task<Result<AuthorizedGrant, RequestError>> AuthorizeAsync(TokenRequest request, ClientInfo clientInfo)
    {
        // Check if there is a handler for the requested grant type.
        // If no handler exists, return an error indicating that the grant type is unsupported.
        if (!_grantHandlers.TryGetValue(request.GrantType, out var grantHandler))
        {
            return new RequestError(
                ErrorCodes.UnsupportedGrantType,
                "The grant type is not supported");
        }

        // Delegate the authorization request to the handler that supports the specified grant type.
        return await grantHandler.AuthorizeAsync(request, clientInfo);
    }
}
