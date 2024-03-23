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
