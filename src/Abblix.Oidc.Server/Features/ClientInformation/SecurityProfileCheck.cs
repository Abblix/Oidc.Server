// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Refuses a tenant declaring a client whose effective security profile mandates a control bundle the client's
/// configuration cannot satisfy, or a profile the server does not define, instead of letting the contradiction
/// surface as a per-request rejection. A tenant selecting no profile is unaffected.
/// </summary>
public sealed class SecurityProfileCheck : ITenantsCheck
{
    /// <inheritdoc />
    public IEnumerable<TenantRefusal> Check(IReadOnlyCollection<TenantDefinition> tenants, OidcOptions options)
        => TenantRefusal.EachOf(tenants, Failures);

    private static List<string> Failures(TenantDefinition tenant)
    {
        var failures = new List<string>();

        // A profile is an enum, and the configuration binder does not check that a value it binds is one the enum
        // defines: a name it does not know throws while a NUMBER outside the range is bound as it stands. Nothing
        // downstream can serve such a value, so it is named here rather than answering 500 on every endpoint that
        // requires a client. Named once for the operator, whether or not any client inherits it.
        failures.AddRange(UndefinedProfile(tenant.DefaultSecurityProfile, nameof(TenantDefinition.DefaultSecurityProfile)));

        foreach (var client in tenant.Clients)
        {
            // The value tested is the EFFECTIVE one, so an undefined default and an undefined client profile are
            // one case rather than two: the consistency walk below resolves whatever this is, and resolving a value
            // the enum does not define throws.
            var effectiveProfile = client.SecurityProfile ?? tenant.DefaultSecurityProfile;
            var undefined = UndefinedProfile(
                effectiveProfile,
                client.SecurityProfile.HasValue
                    ? $"Client '{client.ClientId}'"
                    : $"Client '{client.ClientId}', inheriting {nameof(TenantDefinition.DefaultSecurityProfile)},");

            if (undefined.Count > 0)
            {
                failures.AddRange(undefined);
                continue;
            }

            failures.AddRange(
                from violation in SecurityProfileConsistency.FindViolations(
                    client.EffectiveResponseTypes,
                    client.TokenEndpointAuthMethod,
                    SecurityProfileRequirements.For(client, tenant.DefaultSecurityProfile))
                select $"Client '{client.ClientId}': {violation}.");
        }

        return failures;
    }

    /// <summary>
    /// Names a profile value the enum does not define, as the single-element list the caller adds to its failures.
    /// Empty for a defined value, which is what makes it usable as a guard.
    /// </summary>
    private static IReadOnlyList<string> UndefinedProfile(ClientSecurityProfile profile, string where)
        => Enum.IsDefined(profile)
            ? []
            : [$"{where}: {(int)profile} is not a security profile this server defines."];
}
