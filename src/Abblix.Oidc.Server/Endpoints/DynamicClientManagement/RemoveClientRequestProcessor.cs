// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Performs the storage-level deregistration of a client through the configured
/// <see cref="IClientInfoManager"/> per RFC 7592 section 2.3.
/// </summary>
/// <param name="clientInfoManager">Store used to remove the client record.</param>
/// <param name="clock">Source for the deletion timestamp recorded in the response.</param>
/// <param name="issuerSettings">The settings of the issuer the client is removed from, whose license count it leaves.
/// </param>
public class RemoveClientRequestProcessor(
    IClientInfoManager clientInfoManager,
    TimeProvider clock,
    IIssuerSettings issuerSettings) : IRemoveClientRequestProcessor
{
    /// <summary>
    /// Deletes the addressed client and returns the recorded removal timestamp.
    /// </summary>
    /// <param name="request">A request whose authentication and target client have been validated.</param>
    public async Task<Result<RemoveClientSuccessfulResponse, OidcError>> ProcessAsync(ValidClientRequest request)
    {
        var clientId = request.Client.ClientInfo.ClientId;

        // Only the registration this request was authenticated against: one rotated meanwhile is left
        // to whoever holds the rotated token.
        if (!await clientInfoManager.TryRemoveClientAsync(request.Client))
            return new OidcError(ErrorCodes.InvalidToken, "The access token unauthorized");

        if (LicenseChecker.ClientIssuerOf(issuerSettings) is { } issuerId)
            LicenseChecker.ReleaseClients(issuerId, [clientId]);

        return new RemoveClientSuccessfulResponse(
            ClientId: clientId,
            RemovedAt: clock.GetUtcNow());
    }
}
