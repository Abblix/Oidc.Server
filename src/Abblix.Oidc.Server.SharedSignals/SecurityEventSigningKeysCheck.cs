// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.SecurityEvents.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.SharedSignals;

/// <summary>
/// Refuses a tenant whose signing keys declare none of the algorithms it may sign its security events with, which its
/// security profile, FAPI 1.0 Part 2 section 8.6 and FAPI 2.0 section 5.4.1 among them, and the deployment's
/// allowlist decide: every tenant has a transmitter once Shared Signals is added, and it would sign none of its events,
/// each one left waiting in the outbox.
/// </summary>
/// <param name="securityEvents">What the deployment allows to sign security events with.</param>
/// <param name="custodian">Present when the keys are held by an external custodian, in which case they live outside
/// the tenant's settings and the absence of one there says nothing. It is a registration marker only and is never
/// called here.</param>
internal sealed class SecurityEventSigningKeysCheck(
    IOptions<SecurityEventsOptions> securityEvents,
    IKeyCustodian? custodian = null) : ITenantsCheck
{
    /// <summary>
    /// Registers it beside the other checks of a tenant's keys, so it judges a tenant wherever it enters the server.
    /// </summary>
    /// <param name="services">The service collection.</param>
    public static void Register(IServiceCollection services)
        => services.TryAddEnumerable(ServiceDescriptor.Singleton<ITenantsCheck, SecurityEventSigningKeysCheck>());

    /// <inheritdoc />
    public IEnumerable<TenantRefusal> Check(IReadOnlyCollection<TenantDefinition> tenants, OidcOptions options)
    {
        if (custodian is not null)
            return [];

        // A tenant naming no keys of its own takes them from wherever the host's key provider finds them, which this
        // check cannot see
        return TenantRefusal.EachOf(tenants.Where(tenant => tenant.SigningKeys.Count > 0), Failures);
    }

    private IEnumerable<string> Failures(TenantDefinition tenant)
    {
        var permitted = TenantSecurityEventTokenSigner.AlgorithmsFor(
            SecurityProfileRequirements.For(tenant, null),
            securityEvents.Value);

        if (tenant.SigningKeys.Any(key => TenantSecurityEventTokenSigner.SignsWith(key, permitted)))
            return [];

        return
        [
            permitted.Length > 0
                ? $"no signing key declares an algorithm its security events may be signed with " +
                  $"({string.Join(", ", permitted)}); add one."
                : $"its security profile permits none of the algorithms " +
                  $"{nameof(SecurityEventsOptions)}.{nameof(SecurityEventsOptions.AllowedSigningAlgorithms)} " +
                  "allows, so none of its security events could be signed; name one it permits there.",
        ];
    }
}
