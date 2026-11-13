// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Refuses a tenant where a security profile bounding the signature algorithms is in force - its default, or one a
/// client it declares names - while a token this server signs for itself uses an algorithm that profile does not
/// admit, or is encrypted with one it forbids.
/// </summary>
/// <remarks>
/// FAPI 1.0 Part 2 section 8.6: "For JWS, both clients and authorization servers shall use PS256 or ES256 algorithms",
/// and section 8.6.1 forbids RSA1_5 for any JWE; FAPI 2.0 section 5.4.1 has the server use PS256, ES256 or EdDSA "when
/// creating or processing JWTs". Access, refresh, registration access and initial access tokens take the algorithm the
/// deployment configures for each, not a client's, so the only place to hold them to the profile is the deployment's
/// configuration, judged here before the first one is issued.
/// </remarks>
public sealed class ProfileServiceTokensCheck : ITenantsCheck
{
    /// <inheritdoc />
    public IEnumerable<TenantRefusal> Check(IReadOnlyCollection<TenantDefinition> tenants, OidcOptions options)
    {
        var serviceTokens = options.ServiceTokens;
        var tokens = new[]
        {
            (nameof(serviceTokens.AccessToken), serviceTokens.AccessToken),
            (nameof(serviceTokens.RefreshToken), serviceTokens.RefreshToken),
            (nameof(serviceTokens.RegistrationAccessToken), serviceTokens.RegistrationAccessToken),
            (nameof(serviceTokens.InitialAccessToken), serviceTokens.InitialAccessToken),
        };

        return TenantRefusal.EachOf(tenants, tenant => Failures(tenant, tokens));
    }

    private static IEnumerable<string> Failures(
        TenantDefinition tenant,
        (string Name, ServiceTokenOptions Options)[] tokens)
    {
        // The controls of every profile in force here, the tenant's default and each one a declared client names; an
        // undefined value is the profiles check's to name
        var inForce = new[] { SecurityProfileRequirements.Resolve(tenant.DefaultSecurityProfile) }
            .Concat(
                from client in tenant.Clients
                where Enum.IsDefined(client.SecurityProfile ?? tenant.DefaultSecurityProfile)
                select SecurityProfileRequirements.For(client, tenant.DefaultSecurityProfile))
            .ToArray();

        foreach (var (name, token) in tokens)
        {
            var signing = token.Signing.Algorithm;
            if (Array.Exists(inForce, requirements => !requirements.PermitsSigningAlgorithm(signing)))
            {
                yield return $"ServiceTokens.{name}.Signing.Algorithm is {signing}, which a security profile in force " +
                             $"here does not admit; set it to {string.Join(" or ", SecurityProfileRequirements.FapiSigningAlgorithms)}.";
            }

            if (token.Encrypt == true && token.Encryption.Algorithm is { } encryption &&
                Array.Exists(inForce, requirements => !requirements.PermitsKeyManagementAlgorithm(encryption)))
            {
                yield return $"ServiceTokens.{name}.Encryption.Algorithm is {encryption}, which a security profile in " +
                             "force here forbids.";
            }
        }
    }
}
