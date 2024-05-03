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

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Utils;
using Microsoft.Extensions.Logging;



namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Validates the client specified in the authorization request.
/// This class checks whether the client is registered and authorized to perform the request,
/// as part of the authorization validation process. It plays a crucial role in ensuring that
/// only valid and authorized clients can initiate authorization requests.
/// </summary>
public class ClientValidator : IAuthorizationContextValidator
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ClientValidator"/> class with dependencies for client information
    /// retrieval and logging. The client info provider is used to obtain detailed information about clients,
    /// while the logger records validation activities.
    /// </summary>
    /// <param name="clientInfoProvider">The provider used to retrieve information about clients.</param>
    /// <param name="logger">The logger to be used for recording validation activities and outcomes.</param>
    public ClientValidator(
        IClientInfoProvider clientInfoProvider,
        ILogger<ClientValidator> logger)
    {
        _clientInfoProvider = clientInfoProvider;
        _logger = logger;
    }

    private readonly IClientInfoProvider _clientInfoProvider;
    private readonly ILogger _logger;

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
        var clientInfo = await _clientInfoProvider.TryFindClientAsync(clientId.NotNull(nameof(clientId))).WithLicenseCheck();
        if (clientInfo == null)
        {
            _logger.LogWarning("The client with id {ClientId} was not found", clientId);
            return context.InvalidRequest("The client is not authorized");
        }

        context.ClientInfo = clientInfo;
        return null;
    }
}
