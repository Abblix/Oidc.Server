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
