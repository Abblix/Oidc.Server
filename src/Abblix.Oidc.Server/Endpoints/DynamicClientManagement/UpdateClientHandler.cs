// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Handles client configuration update requests in OAuth 2.0 Dynamic Client Registration Management protocol per RFC 7592.
/// Coordinates validation and processing to securely update registered client information.
/// </summary>
/// <param name="validator">Validates client authentication and authorization for configuration updates.</param>
/// <param name="processor">Updates and formats client configuration data.</param>
public class UpdateClientHandler(
    IUpdateClientRequestValidator validator,
    IUpdateClientRequestProcessor processor) : IUpdateClientHandler
{
    /// <summary>
    /// Processes a client configuration update request per RFC 7592 Section 2.2.
    /// </summary>
    /// <param name="request">The update request containing client authentication and updated metadata.</param>
    /// <returns>A task that results in updated client configuration or an error response.</returns>
    /// <exception cref="UnexpectedTypeException">Thrown if the validation result does not match expected types.</exception>
    /// <remarks>
    /// This method serves as a critical part of dynamic client management, allowing for the secure update of client
    /// configurations. It ensures that only valid and authorized requests are processed, safeguarding against
    /// unauthorized modifications to client information.
    /// </remarks>
    public async Task<Result<ReadClientSuccessfulResponse, OidcError>> HandleAsync(UpdateClientRequest request)
    {
        var validationResult = await validator.ValidateAsync(request);
        return await validationResult.BindAsync(processor.ProcessAsync);
    }
}
