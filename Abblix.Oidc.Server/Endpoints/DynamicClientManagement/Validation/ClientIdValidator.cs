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

using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// This class validates the client ID specified in a client registration request by checking if it exists and is authorized.
/// </summary>
public class ClientIdValidator : IClientRegistrationContextValidator
{
    /// <summary>
    /// Initializes a new instance of the ClientIdValidator class with a client info provider and a logger.
    /// </summary>
    /// <param name="clientInfoProvider">The client info provider to retrieve client information.</param>
    /// <param name="logger">The logger to be used for logging purposes.</param>
    public ClientIdValidator(
        IClientInfoProvider clientInfoProvider,
        ILogger<ClientIdValidator> logger)
    {
        _clientInfoProvider = clientInfoProvider;
        _logger = logger;
    }

    private readonly IClientInfoProvider _clientInfoProvider;
    private readonly ILogger _logger;

    /// <summary>
    /// Validates the client specified in the client registration request by checking if it already exists and is registered.
    /// </summary>
    /// <param name="context">The validation context containing client registration information.</param>
    /// <returns>A ClientRegistrationValidationError if the validation fails, or null if the request is valid.</returns>
    public async Task<ClientRegistrationValidationError?> ValidateAsync(ClientRegistrationValidationContext context)
    {
        var clientId = context.Request.ClientId;
        if (clientId.HasValue())
        {
            var clientInfo = await _clientInfoProvider.TryFindClientAsync(clientId).WithLicenseCheck();
            if (clientInfo != null)
            {
                _logger.LogWarning("The client with id {ClientId} is already registered", clientId);
                return ErrorFactory.InvalidClientMetadata($"The client with id={clientId} is already registered");
            }
        }
        return null;
    }
}
