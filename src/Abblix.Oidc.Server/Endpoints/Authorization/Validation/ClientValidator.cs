// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Licensing;
using Microsoft.Extensions.Logging;



namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Validates the client specified in the authorization request.
/// This class checks whether the client is registered and authorized to perform the request,
/// as part of the authorization validation process. It plays a crucial role in ensuring that
/// only valid and authorized clients can initiate authorization requests.
/// </summary>
/// <param name="logger">The logger to be used for recording validation activities and outcomes.</param>
/// <param name="clientInfoProvider">The provider used to retrieve information about clients.</param>
public partial class ClientValidator(
    ILogger<ClientValidator> logger,
    IClientInfoProvider clientInfoProvider) : IAuthorizationContextValidator
{
    /// <summary>
    /// Asynchronously validates the client specified in the authorization request.
    /// Ensures the client is recognized and authorized to make the request.
    /// </summary>
    /// <param name="context">
    /// The validation context containing details of the authorization request and client information.
    /// </param>
    /// <returns>
    /// An <see cref="AuthorizationRequestValidationError"/> if the client is not found or not authorized,
    /// or null if the client is valid.
    /// </returns>
    public async Task<AuthorizationRequestValidationError?> ValidateAsync(AuthorizationValidationContext context)
    {
        var clientId = context.Request.ClientId;
        if (clientId is null)
        {
            return context.Error(ErrorCodes.UnauthorizedClient, "The client id is required");
        }

        var clientInfo = await clientInfoProvider.TryFindClientAsync(clientId).WithLicenseCheck();
        if (clientInfo == null)
        {
            LogClientNotFound(clientId);
            return context.Error(ErrorCodes.UnauthorizedClient, "The client is not authorized");
        }

        context.ClientInfo = clientInfo;
        return null;
    }
}
