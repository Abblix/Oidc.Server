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

using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Model;

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
    public async Task<UserInfoResponse> HandleAsync(
        UserInfoRequest userInfoRequest,
        ClientRequest clientRequest)
    {
        var validationResult = await _validator.ValidateAsync(userInfoRequest, clientRequest);

        return validationResult switch
        {
            ValidUserInfoRequest validRequest => await _processor.ProcessAsync(validRequest),

            UserInfoRequestError { Error: var error, ErrorDescription: var description }
                => new UserInfoErrorResponse(error, description),

            _ => throw new UnexpectedTypeException(nameof(validationResult), validationResult.GetType()),
        };
    }
}
