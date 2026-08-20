// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.UserInfo;

/// <summary>
/// Handles user information requests in an OpenID Connect compliant manner. It ensures that requests for user info
/// are correctly validated and processed, returning the requested user information if the request is authorized.
/// </summary>
/// <param name="validator">An implementation of <see cref="IUserInfoRequestValidator"/> responsible for validating
/// user info requests against OpenID Connect specifications.</param>
/// <param name="processor">An implementation of <see cref="IUserInfoRequestProcessor"/> responsible for processing
/// validated requests and retrieving user information.</param>
public class UserInfoHandler(
    IUserInfoRequestValidator validator,
    IUserInfoRequestProcessor processor) : IUserInfoHandler
{
    /// <summary>
    /// Asynchronously processes a user info request by first validating it and then, if validation is successful,
    /// retrieving the requested user information.
    /// </summary>
    /// <param name="userInfoRequest">The user info request containing necessary parameters such as the access token.
    /// </param>
    /// <param name="clientRequest">Additional information about the client making the request, useful for contextual
    /// validation.</param>
    /// <returns>
    /// A <see cref="Task"/> that resolves to a <see cref="UserInfoFoundResponse"/>, which contains the requested user
    /// information in case of a valid request, or an <see cref="OidcError"/> detailing the reason for failure.
    /// </returns>
    /// <remarks>
    /// This method is pivotal for ensuring that only authenticated and authorized requests gain access to sensitive
    /// user information, in line with OpenID Connect protocols. It leverages the validator to ensure requests meet
    /// OIDC standards and the processor to fetch and return the relevant user information securely.
    /// </remarks>
    public async Task<Result<UserInfoFoundResponse, OidcError>> HandleAsync(
        UserInfoRequest userInfoRequest,
        ClientRequest clientRequest)
    {
        var validationResult = await validator.ValidateAsync(userInfoRequest, clientRequest);

        return await validationResult.BindAsync(processor.ProcessAsync);
    }
}
