// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Refuses a tenant with no encryption key while a service token is asked to be encrypted, instead of failing every
/// token issuance of that type.
/// </summary>
/// <param name="custodian">Present when the keys are held, or sealed, by an external custodian, in which case they
/// live outside the tenant's settings and the emptiness of those says nothing. It is a registration marker only and
/// is never called here.</param>
public sealed class ServiceTokenEncryptionKeysCheck(IKeyCustodian? custodian = null) : ITenantsCheck
{
    /// <inheritdoc />
    public IEnumerable<TenantRefusal> Check(IReadOnlyCollection<TenantDefinition> tenants, OidcOptions options)
    {
        if (custodian is not null)
            return [];

        // Only an explicit true is refused: the null default states nothing, and a host that never touched the
        // setting keeps starting and issuing a signed JWS
        var serviceTokens = options.ServiceTokens;
        var encrypted = new[]
            {
                (nameof(serviceTokens.AccessToken), serviceTokens.AccessToken),
                (nameof(serviceTokens.RefreshToken), serviceTokens.RefreshToken),
                (nameof(serviceTokens.RegistrationAccessToken), serviceTokens.RegistrationAccessToken),
                (nameof(serviceTokens.InitialAccessToken), serviceTokens.InitialAccessToken),
            }
            .Where(token => token.Item2.Encrypt == true)
            .Select(token => token.Item1)
            .ToArray();

        return TenantRefusal.EachOf(
            tenants.Where(tenant => tenant.EncryptionKeys.Count == 0),
            _ => encrypted.Select(tokenType =>
                $"ServiceTokens.{tokenType}.Encrypt is true, but no encryption key is available: " +
                $"{nameof(TenantDefinition)}.{nameof(TenantDefinition.EncryptionKeys)} is empty and no external " +
                $"key custodian is registered. Configure an encryption key, or set ServiceTokens.{tokenType}.Encrypt " +
                "to false to issue this token as a signed JWS."));
    }
}
