// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Refuses a tenant declaring a client its security profile holds to certain signature algorithms (FAPI 1.0 Part 2
/// section 8.6, FAPI 2.0 section 5.4.1) when no signing key of the tenant produces an algorithm the client is
/// configured for, instead of failing when the first ID token or JWT response is signed for it.
/// </summary>
/// <param name="custodian">Present when the keys are held by an external custodian, in which case they live outside
/// the tenant's settings and the absence of one there says nothing. It is a registration marker only and is never
/// called here.</param>
public sealed class ProfileSigningKeysCheck(IKeyCustodian? custodian = null) : ITenantsCheck
{
    /// <inheritdoc />
    public IEnumerable<TenantRefusal> Check(IReadOnlyCollection<TenantDefinition> tenants, OidcOptions options)
    {
        if (custodian is not null)
            return [];

        // A tenant naming no keys of its own takes them from wherever the host's key provider finds them, which this
        // check cannot see
        return TenantRefusal.EachOf(tenants.Where(tenant => tenant.SigningKeys.Count > 0), Failures);
    }

    private static IEnumerable<string> Failures(TenantDefinition tenant)
        => from client in tenant.Clients
           where Enum.IsDefined(SecurityProfileRequirements.ProfileNamedFor(tenant, client)) &&
                 SecurityProfileRequirements.For(client, tenant.DefaultSecurityProfile).RequireFapiSigningAlgorithms
           from setting in SignedForTheClient(client)
           where setting.Algorithm is { } algorithm && !tenant.SigningKeys.Any(key => key.CanPerform(algorithm))
           select $"Client '{client.ClientId}': {setting.Name} is {setting.Algorithm}, which no signing key of the " +
                  "tenant produces.";

    private static (string Name, string? Algorithm)[] SignedForTheClient(ClientInfo client) =>
    [
        (nameof(ClientInfo.IdentityTokenSignedResponseAlgorithm), client.IdentityTokenSignedResponseAlgorithm),
        (nameof(ClientInfo.AuthorizationSignedResponseAlgorithm), client.AuthorizationSignedResponseAlgorithm),
        (nameof(ClientInfo.LogoutTokenSignedResponseAlgorithm), client.LogoutTokenSignedResponseAlgorithm),
        (nameof(ClientInfo.UserInfoSignedResponseAlgorithm),
            SecurityProfileConsistency.SignedOrNull(client.UserInfoSignedResponseAlgorithm)),
        (nameof(ClientInfo.IntrospectionSignedResponseAlgorithm),
            SecurityProfileConsistency.SignedOrNull(client.IntrospectionSignedResponseAlgorithm)),
    ];
}
