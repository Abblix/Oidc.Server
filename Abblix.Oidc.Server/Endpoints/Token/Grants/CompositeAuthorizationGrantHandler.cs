// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
