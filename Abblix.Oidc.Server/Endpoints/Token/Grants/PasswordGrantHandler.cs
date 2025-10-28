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
/// Handles the authorization process for the password grant type within the OAuth 2.0 framework.
/// This handler validates the user's credentials and processes token requests based on the password grant type.
/// The password grant type allows clients to directly exchange a user's credentials (username and password)
/// for an access token, typically for trusted clients.
/// </summary>
public class PasswordGrantHandler : IAuthorizationGrantHandler
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PasswordGrantHandler"/> class.
    /// The constructor sets up the required services for validating user credentials and parameters.
    /// The parameter validator ensures the required parameters for this grant type are present,
    /// while the user credentials authenticator is responsible for verifying the username and password.
    /// </summary>
    /// <param name="parameterValidator">A service for validating required request parameters.</param>
    /// <param name="userCredentialsAuthenticator">A service for authenticating the user's credentials.</param>
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
    /// Specifies the grant type that this handler supports, which is the "password" grant type.
    /// This ensures that this handler is only invoked when processing requests with the password grant type.
    /// </summary>
    public IEnumerable<string> GrantTypesSupported
    {
        get { yield return GrantTypes.Password; }
    }

    /// <summary>
    /// Asynchronously processes the token request using the password grant type.
    /// The handler ensures the request contains the necessary parameters, validates the user's credentials,
    /// and then proceeds to authorize the request if the credentials are valid.
    /// It delegates credential validation to the user credentials authenticator, which handles the security
    /// checks related to user authentication.
    /// </summary>
    /// <param name="request">The token request containing the user's credentials and other parameters.</param>
    /// <param name="clientInfo">Information about the client making the request, used for validation and context.
    /// </param>
    /// <returns>A task that completes with the authorization result, which could be an error or successful grant.
    /// </returns>
    public Task<GrantAuthorizationResult> AuthorizeAsync(TokenRequest request, ClientInfo clientInfo)
    {
        // Ensure that the request contains the required username and password parameters.
        _parameterValidator.Required(request.UserName, nameof(request.UserName));
        _parameterValidator.Required(request.Password, nameof(request.Password));
        
        // Extract relevant details from the request and prepare the authorization context.
        var userName = request.UserName;
        var password = request.Password;
        var scope = request.Scope;
        var context = new AuthorizationContext(clientInfo.ClientId, scope, null);

        // Delegate the actual user credential validation and authentication to the custom authenticator.
        return _userCredentialsAuthenticator.ValidateAsync(userName, password, context);
    }
}
