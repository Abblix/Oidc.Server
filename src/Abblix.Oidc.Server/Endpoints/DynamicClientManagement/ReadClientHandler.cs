// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
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
    /// Validates the registration access token and resolves the addressed client, then delegates
    /// to the processor to build the read-client response per RFC 7592 section 2.1.
    /// </summary>
    /// <param name="clientRequest">The incoming RFC 7592 read request.</param>
    /// <returns>The current client metadata or an error result.</returns>
    public async Task<Result<ReadClientSuccessfulResponse, OidcError>> HandleAsync(ClientRequest clientRequest)
    {
        var validationResult = await validator.ValidateAsync(clientRequest);
        return await validationResult.BindAsync(processor.ProcessAsync);
    }
}
