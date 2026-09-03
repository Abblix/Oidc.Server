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
/// Default implementation of <see cref="IRemoveClientHandler"/> that authenticates the
/// registration access token via <see cref="IClientRequestValidator"/> and, on success,
/// delegates to the processor to delete the client per RFC 7592 section 2.3.
/// </summary>
/// <param name="validator">Validator for the registration access token and target client.</param>
/// <param name="processor">Processor that performs the actual deletion.</param>
public class RemoveClientHandler(
    IClientRequestValidator validator,
    IRemoveClientRequestProcessor processor) : IRemoveClientHandler
{
    /// <summary>
    /// Validates the request, then deletes the addressed client per RFC 7592 section 2.3.
    /// </summary>
    /// <param name="clientRequest">The DELETE request authenticated by a registration access token.</param>
    public async Task<Result<RemoveClientSuccessfulResponse, OidcError>> HandleAsync(ClientRequest clientRequest)
    {
        var validationResult = await validator.ValidateAsync(clientRequest);

        return await validationResult.BindAsync(processor.ProcessAsync);
    }
}
