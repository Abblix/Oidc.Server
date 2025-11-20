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
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Handles client configuration retrieval requests in OAuth 2.0 Dynamic Client Registration protocol.
/// Coordinates validation and processing to securely fetch registered client information.
/// </summary>
/// <param name="validator">Validates client authentication and authorization for configuration access.</param>
/// <param name="processor">Retrieves and formats client configuration data.</param>
public class ReadClientHandler(
    IClientRequestValidator validator,
    IReadClientRequestProcessor processor) : IReadClientHandler
{
    /// <summary>
    /// Processes a client configuration read request.
    /// </summary>
    /// <param name="clientRequest">The authenticated client request with registration access credentials.</param>
    /// <returns>Client configuration data or an error if validation fails.</returns>
    public async Task<Result<ReadClientSuccessfulResponse, OidcError>> HandleAsync(Model.ClientRequest clientRequest)
    {
        var validationResult = await validator.ValidateAsync(clientRequest);

        return await validationResult.BindAsync(processor.ProcessAsync);
    }
}
