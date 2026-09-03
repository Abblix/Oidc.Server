// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Performs the storage-level deregistration of a client through the configured
/// <see cref="IClientInfoManager"/> per RFC 7592 section 2.3.
/// </summary>
/// <param name="clientInfoManager">Store used to remove the client record.</param>
/// <param name="registrationAccessTokenStore">Store holding the client's registration-token binding.</param>
/// <param name="clock">Source for the deletion timestamp recorded in the response.</param>
public class RemoveClientRequestProcessor(
    IClientInfoManager clientInfoManager,
    IRegistrationAccessTokenStore registrationAccessTokenStore,
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

        // Drop the registration access token binding so it does not outlive the client.
        await registrationAccessTokenStore.RemoveAsync(clientId);

        return new RemoveClientSuccessfulResponse(
            ClientId: clientId,
            RemovedAt: clock.GetUtcNow());
    }
}
