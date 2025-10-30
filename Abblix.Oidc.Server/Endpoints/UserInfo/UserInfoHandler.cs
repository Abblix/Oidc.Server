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
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.UserInfo;

/// <summary>
/// Handles user information requests in an OpenID Connect compliant manner. It ensures that requests for user info
/// are correctly validated and processed, returning the requested user information if the request is authorized.
/// </summary>
public class UserInfoHandler : IUserInfoHandler
{
    /// <summary>
    /// Initializes a new instance of the <see cref="UserInfoHandler"/> class, setting up the necessary validator
    /// and processor for handling user info requests.
    /// </summary>
    /// <param name="validator">An implementation of <see cref="IUserInfoRequestValidator"/> responsible for validating
    /// user info requests against OpenID Connect specifications.</param>
    /// <param name="processor">An implementation of <see cref="IUserInfoRequestProcessor"/> responsible for processing
    /// validated requests and retrieving user information.</param>
    public UserInfoHandler(
        IUserInfoRequestValidator validator,
        IUserInfoRequestProcessor processor)
    {
        _validator = validator;
        _processor = processor;
    }

    private readonly IUserInfoRequestValidator _validator;
    private readonly IUserInfoRequestProcessor _processor;

    /// <summary>
    /// Asynchronously processes a user info request by first validating it and then, if validation is successful,
    /// retrieving the requested user information.
    /// </summary>
    /// <param name="userInfoRequest">The user info request containing necessary parameters such as the access token.
    /// </param>
    /// <param name="clientRequest">Additional information about the client making the request, useful for contextual
    /// validation.</param>
    /// <returns>
    /// A <see cref="Task"/> that resolves to a <see cref="UserInfoResponse"/>, which contains the requested user
    /// information in case of a valid request, or an error detailing the reason for failure.
    /// </returns>
    /// <remarks>
    /// This method is pivotal for ensuring that only authenticated and authorized requests gain access to sensitive
    /// user information, in line with OpenID Connect protocols. It leverages the validator to ensure requests meet
    /// OIDC standards and the processor to fetch and return the relevant user information securely.
    /// </remarks>
    public async Task<Result<UserInfoFoundResponse, AuthError>> HandleAsync(
        UserInfoRequest userInfoRequest,
        ClientRequest clientRequest)
    {
        var validationResult = await _validator.ValidateAsync(userInfoRequest, clientRequest);

        return await validationResult.BindAsync(_processor.ProcessAsync);
    }
}
