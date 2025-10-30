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
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.EndSession.Validation;

/// <summary>
/// Validates the client associated with an end-session request.
/// </summary>
/// <remarks>
/// This class checks if the client exists and is authorized for the end-session request.
/// If the client is not found, it returns an error indicating an unauthorized client.
/// </remarks>
public class ClientValidator : IEndSessionContextValidator
{
    /// <summary>
    /// Initializes a new instance of the ClientValidator class with a client info provider and a logger.
    /// </summary>
    /// <param name="clientInfoProvider">The client info provider to retrieve client information.</param>
    /// <param name="logger">The logger to be used for logging purposes.</param>
    public ClientValidator(
        ILogger<ClientValidator> logger,
        IClientInfoProvider clientInfoProvider)
    {
        _clientInfoProvider = clientInfoProvider;
        _logger = logger;
    }

    private readonly IClientInfoProvider _clientInfoProvider;
    private readonly ILogger _logger;

    /// <summary>
    /// Validates the client associated with an end-session request.
    /// </summary>
    /// <param name="context">The validation context containing client information.</param>
    /// <returns>An error if the validation fails, or null if the request is valid.</returns>
    public async Task<OidcError?> ValidateAsync(EndSessionValidationContext context)
    {
        if (!context.ClientId.HasValue())
            return null;

        var clientInfo = await _clientInfoProvider.TryFindClientAsync(context.ClientId).WithLicenseCheck();
        if (clientInfo == null)
        {
            _logger.LogWarning("The client with id {ClientId} was not found", Sanitized.Value(context.ClientId));
            return new OidcError(
                ErrorCodes.UnauthorizedClient,
                "The client is not authorized");
        }

        context.ClientInfo = clientInfo;
        return null;
    }
}
