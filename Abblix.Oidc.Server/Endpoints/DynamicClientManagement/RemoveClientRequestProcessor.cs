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
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Handles the backend logic for processing requests to remove clients from the system. This processor uses the provided
/// client information manager to execute the removal operation.
/// </summary>
/// <param name="clientInfoManager">An instance of <see cref="IClientInfoManager"/> used to interact with and
/// manage client information, facilitating the removal of clients based on their identifiers.</param>
/// <param name="clock">Provides the current time for timestamping the removal operation.</param>
public class RemoveClientRequestProcessor(
    IClientInfoManager clientInfoManager,
    TimeProvider clock) : IRemoveClientRequestProcessor
{
    /// <summary>
    /// Asynchronously executes the process of removing a client based on the provided request.
    /// This method ensures the client specified in the request is removed from the system,
    /// reflecting changes in the client registry.
    /// </summary>
    /// <param name="request">An instance of <see cref="ValidClientRequest"/> containing the details of
    /// the client to be removed, including its unique identifier.</param>
    /// <returns>A task that, upon completion, yields a <see cref="Result{RemoveClientSuccessfulResponse, AuthError}"/> indicating the successful
    /// removal of the client.</returns>
    /// <remarks>
    /// This method calls upon the <see cref="IClientInfoManager"/> to remove the specified client.
    /// It is expected that the request passed to this method has been validated beforehand,
    /// ensuring that the client exists and the initiator of the request has the authority to perform
    /// the removal operation.
    /// </remarks>
    public async Task<Result<RemoveClientSuccessfulResponse, OidcError>> ProcessAsync(ValidClientRequest request)
    {
        var clientId = request.ClientInfo.ClientId;
        await clientInfoManager.RemoveClientAsync(clientId);

        return new RemoveClientSuccessfulResponse(
            ClientId: clientId,
            RemovedAt: clock.GetUtcNow());
    }
}
