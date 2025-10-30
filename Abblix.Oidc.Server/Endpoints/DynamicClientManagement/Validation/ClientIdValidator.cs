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
    /// <returns>A AuthError if the validation fails, or null if the request is valid.</returns>
    public async Task<OidcError?> ValidateAsync(ClientRegistrationValidationContext context)
    {
        var clientId = context.Request.ClientId;
        if (clientId.HasValue())
        {
            var clientInfo = await _clientInfoProvider.TryFindClientAsync(clientId).WithLicenseCheck();
            if (clientInfo != null)
            {
                _logger.LogWarning("The client with id {ClientId} is already registered", Sanitized.Value(clientId));
                return ErrorFactory.InvalidClientMetadata($"The client with id={clientId} is already registered");
            }
        }
        return null;
    }
}
