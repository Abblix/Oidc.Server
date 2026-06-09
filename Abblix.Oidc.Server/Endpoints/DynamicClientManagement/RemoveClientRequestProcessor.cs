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
/// Performs the storage-level deregistration of a client through the configured
/// <see cref="IClientInfoManager"/> per RFC 7592 §2.3.
/// </summary>
/// <param name="clientInfoManager">Store used to remove the client record.</param>
/// <param name="clock">Source for the deletion timestamp recorded in the response.</param>
public class RemoveClientRequestProcessor(
    IClientInfoManager clientInfoManager,
    TimeProvider clock) : IRemoveClientRequestProcessor
{
    /// <summary>
    /// Deletes the addressed client and returns the recorded removal timestamp.
    /// </summary>
    /// <param name="request">A request whose authentication and target client have been validated.</param>
    public async Task<Result<RemoveClientSuccessfulResponse, OidcError>> ProcessAsync(ValidClientRequest request)
    {
        var clientId = request.ClientInfo.ClientId;
        await clientInfoManager.RemoveClientAsync(clientId);

        return new RemoveClientSuccessfulResponse(
            ClientId: clientId,
            RemovedAt: clock.GetUtcNow());
    }
}
