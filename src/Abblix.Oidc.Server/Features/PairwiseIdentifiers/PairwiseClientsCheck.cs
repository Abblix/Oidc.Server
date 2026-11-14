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

namespace Abblix.Oidc.Server.Features.PairwiseIdentifiers;

/// <summary>
/// Refuses a tenant declaring clients that take pairwise subject identifiers without a pairwise key to seal them.
/// </summary>
/// <remarks>
/// Such a client is served and fails every token request with a 500, while discovery says pairwise is not
/// supported, since the tenant's subject type converter issues pairwise identifiers only once the tenant declares
/// its key.
/// </remarks>
public sealed class PairwiseClientsCheck : ITenantsCheck
{
    /// <inheritdoc />
    public IEnumerable<TenantRefusal> Check(IReadOnlyCollection<TenantDefinition> tenants, OidcOptions options)
        => TenantRefusal.EachOf(tenants, Failures);

    private static IEnumerable<string> Failures(TenantDefinition tenant)
    {
        var pairwise = tenant.Clients
            .Where(client => client.SubjectType == SubjectTypes.Pairwise)
            .Select(client => $"'{client.ClientId}'")
            .ToArray();

        if (tenant.PairwiseSubject is null && pairwise.Length > 0)
        {
            yield return
                $"The clients {string.Join(", ", pairwise)} take pairwise subject identifiers, but no pairwise key is " +
                "configured to seal them.";
        }
    }
}
