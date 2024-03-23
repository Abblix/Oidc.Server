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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;


namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// This class is responsible for handling the password grant type
/// as part of the IAuthorizationGrantHandler process.
/// </summary>
public class PasswordGrantHandler : IAuthorizationGrantHandler
{
    /// <summary>
    /// Initializes a new instance of the PasswordGrantHandler class.
    /// </summary>
    public PasswordGrantHandler(
        IParameterValidator parameterValidator,
        IUserCredentialsAuthenticator userCredentialsAuthenticator)
    {
        _parameterValidator = parameterValidator;
        _userCredentialsAuthenticator = userCredentialsAuthenticator;
    }

    private readonly IParameterValidator _parameterValidator;
    private readonly IUserCredentialsAuthenticator _userCredentialsAuthenticator;

    /// <summary>
    /// Gets the grant type this handler supports.
    /// </summary>
    public IEnumerable<string> GrantTypesSupported
    {
        get { yield return GrantTypes.Password; }
    }

    /// <summary>
    /// Authorizes the token request asynchronously using the password grant type.
    /// </summary>
    /// <param name="request">The token request to authorize.</param>
    /// <param name="clientInfo">The client information associated with the request.</param>
    /// <returns>A task representing the result of the authorization process, containing a GrantAuthorizationResult object.</returns>
    public Task<GrantAuthorizationResult> AuthorizeAsync(TokenRequest request, ClientInfo clientInfo)
    {
        _parameterValidator.Required(request.UserName, nameof(request.UserName));
        _parameterValidator.Required(request.Password, nameof(request.Password));
        
        var userName = request.UserName;
        var password = request.Password;
        var scope = request.Scope;
        var context = new AuthorizationContext(clientInfo.ClientId, scope, null);

        return _userCredentialsAuthenticator.ValidateAsync(userName, password, context);
    }
}
