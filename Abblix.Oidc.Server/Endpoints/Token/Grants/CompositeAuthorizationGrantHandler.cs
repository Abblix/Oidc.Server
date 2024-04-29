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

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// Represents a composite handler that manages multiple authorization grant handlers. This class allows for the delegation
/// of authorization requests to specific handlers based on the grant type specified in the request. It supports a dynamic
/// registration of grant handlers, facilitating the extension and customization of the authorization process to accommodate
/// various grant types defined by the OAuth 2.0 specification.
/// </summary>
public class CompositeAuthorizationGrantHandler: IAuthorizationGrantHandler
{
    public CompositeAuthorizationGrantHandler(IEnumerable<IAuthorizationGrantHandler> grantHandlers)
    {
        _grantHandlers = new Dictionary<string, IAuthorizationGrantHandler>(
            from handler in grantHandlers
            from grantType in handler.GrantTypesSupported
            select new KeyValuePair<string, IAuthorizationGrantHandler>(grantType, handler),
            StringComparer.OrdinalIgnoreCase);
    }

    private readonly Dictionary<string, IAuthorizationGrantHandler> _grantHandlers;

    /// <summary>
    /// The collection of grant types supported by the composite handler, aggregating the grant types
    /// from all registered individual grant handlers.
    /// </summary>
    public IEnumerable<string> GrantTypesSupported => _grantHandlers.Keys;

    /// <summary>
    /// Asynchronously authorizes a token request based on its grant type. Delegates the authorization
    /// process to the appropriate grant handler that supports the specified grant type in the request.
    /// </summary>
    /// <param name="request">The token request containing the grant type and other relevant data.</param>
    /// <param name="clientInfo">Client information associated with the request, used for validation and processing.</param>
    /// <returns>A task that resolves to a <see cref="GrantAuthorizationResult"/>,
    /// indicating the outcome of the authorization attempt.</returns>
    public async Task<GrantAuthorizationResult> AuthorizeAsync(TokenRequest request, ClientInfo clientInfo)
    {
        if (!_grantHandlers.TryGetValue(request.GrantType, out var grantHandler))
        {
            return new InvalidGrantResult(
                ErrorCodes.UnsupportedGrantType,
                "The grant type is not supported");
        }

        if (!clientInfo.AllowedGrantTypes.Contains(request.GrantType))
        {
            return new InvalidGrantResult(
                ErrorCodes.UnauthorizedClient,
                "The grant type is not allowed for this client");
        }

        return await grantHandler.AuthorizeAsync(request, clientInfo);
    }
}
