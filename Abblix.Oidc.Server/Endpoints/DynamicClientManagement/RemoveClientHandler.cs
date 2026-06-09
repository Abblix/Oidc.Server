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
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Default implementation of <see cref="IRemoveClientHandler"/> that authenticates the
/// registration access token via <see cref="IClientRequestValidator"/> and, on success,
/// delegates to the processor to delete the client per RFC 7592 §2.3.
/// </summary>
/// <param name="validator">Validator for the registration access token and target client.</param>
/// <param name="processor">Processor that performs the actual deletion.</param>
public class RemoveClientHandler(
    IClientRequestValidator validator,
    IRemoveClientRequestProcessor processor) : IRemoveClientHandler
{
    /// <summary>
    /// Validates the request, then deletes the addressed client per RFC 7592 §2.3.
    /// </summary>
    /// <param name="clientRequest">The DELETE request authenticated by a registration access token.</param>
    public async Task<Result<RemoveClientSuccessfulResponse, OidcError>> HandleAsync(ClientRequest clientRequest)
    {
        var validationResult = await validator.ValidateAsync(clientRequest);

        return await validationResult.BindAsync(processor.ProcessAsync);
    }
}
