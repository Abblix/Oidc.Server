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

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;
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
    public async Task<EndSessionRequestValidationError?> ValidateAsync(EndSessionValidationContext context)
    {
        if (!context.ClientId.HasValue())
            return null;

        var clientInfo = await _clientInfoProvider.TryFindClientAsync(context.ClientId).WithLicenseCheck();
        if (clientInfo == null)
        {
            _logger.LogWarning("The client with id {ClientId} was not found", context.ClientId);
            return new EndSessionRequestValidationError(
                ErrorCodes.UnauthorizedClient,
                "The client is not authorized");
        }

        context.ClientInfo = clientInfo;
        return null;
    }
}
