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
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Builds the RFC 7592 section 2.1 read-client response from stored client metadata. The
/// <c>client_secret</c> is intentionally omitted because secrets are persisted only as
/// hashes; a registration access token bearing the client's current jti is re-issued so the
/// client can keep using the management endpoint after the read, without invalidating the token
/// it presented (read stays idempotent - only update rotates the jti).
/// </summary>
public class ReadClientRequestProcessor(
    IRegistrationAccessTokenService registrationAccessTokenService,
    TimeProvider clock) : IReadClientRequestProcessor
{
    /// <inheritdoc />
    public async Task<Result<ReadClientSuccessfulResponse, OidcError>> ProcessAsync(TenantDefinition tenant, ValidClientRequest request)
    {
        var client = request.Client.ClientInfo;

        var issuedAt = clock.GetUtcNow();
        // Reuse the jti the request was authenticated with, so the token the client just presented
        // stays valid; only update rotates it (read is idempotent). Read from the store again instead,
        // a request racing a rotation would hand the holder of the old token a current one.
        var registrationAccessToken = await registrationAccessTokenService.IssueTokenAsync(
            tenant,
            client.ClientId, issuedAt, null, request.Client.RegistrationAccessTokenId);

        return new ReadClientSuccessfulResponse(RegisteredClientMetadata.Of(client))
        {
            ClientId = client.ClientId,
            ClientSecret = null, // Client secrets are stored as hashes and cannot be retrieved
            ClientSecretExpiresAt = GetClientSecretExpiresAt(client),
            RegistrationAccessToken = registrationAccessToken,
        };
    }

    /// <summary>
    /// Determines the latest expiration time among all client secrets.
    /// </summary>
    /// <param name="client">The client information containing secret configurations.</param>
    /// <returns>
    /// The latest expiration time if any secrets have expiration dates; otherwise, null.
    /// Returns null if the client has no secrets or all secrets have no expiration.
    /// </returns>
    private static DateTimeOffset? GetClientSecretExpiresAt(ClientInfo client)
    {
        if (client.ClientSecrets == null)
            return null;

        DateTimeOffset? result = null;
        foreach (var expiresAt in client.ClientSecrets.Select(secret => secret.ExpiresAt))
        {
            if (!expiresAt.HasValue)
                continue;

            if (!result.HasValue || result.Value < expiresAt.Value)
                result = expiresAt;
        }

        return result;
    }
}
