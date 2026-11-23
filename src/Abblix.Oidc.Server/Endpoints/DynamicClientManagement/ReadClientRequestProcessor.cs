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
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Builds the RFC 7592 section 2.1 read-client response from stored client metadata. The <c>client_secret</c> is
/// returned when the tenant kept it encrypted (<see cref="TenantDefinition.ClientSecretEncryption"/>), as section 3 and
/// Appendix A.1 ask, and left out otherwise, since only its hash is kept; a registration access token bearing the
/// client's current jti is re-issued so the client can keep using the management endpoint after the read, without
/// invalidating the token it presented (read stays idempotent - only update rotates the jti).
/// </summary>
public class ReadClientRequestProcessor(
    IRegistrationAccessTokenService registrationAccessTokenService,
    TimeProvider clock) : IReadClientRequestProcessor
{
    /// <summary>
    /// Creates the processor returning the client its secret where the tenant kept it encrypted.
    /// </summary>
    /// <param name="registrationAccessTokenService">Issues the registration access token.</param>
    /// <param name="clock">Provides the issue time.</param>
    /// <param name="clientSecretEncryptor">Decrypts the secret the tenant kept encrypted.</param>
    [ActivatorUtilitiesConstructor]
    public ReadClientRequestProcessor(
        IRegistrationAccessTokenService registrationAccessTokenService,
        TimeProvider clock,
        IClientSecretEncryptor clientSecretEncryptor)
        : this(registrationAccessTokenService, clock)
    {
        _clientSecretEncryptor = clientSecretEncryptor;
    }

    /// <summary>
    /// Decrypts the secret, or null for a processor built without it, which answers without the secret.
    /// </summary>
    private readonly IClientSecretEncryptor? _clientSecretEncryptor;

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
            ClientSecret = IssuedClientSecret.Of(tenant, client, _clientSecretEncryptor),
            ClientSecretExpiresAt = IssuedClientSecret.ExpiresAt(client),
            RegistrationAccessToken = registrationAccessToken,
        };
    }
}
