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
/// Refuses a tenant declaring a client whose cross-client subject token exchange setting is none of the values the
/// enumeration names, that is <see cref="CrossClientSubjectTokenExchange.AddressedToClient"/> while the client names no
/// location of its own, or whose locations name the tenant's issuer.
/// </summary>
/// <remarks>
/// Configuration binds a number to an enumeration whatever its value, so a mistyped one would otherwise reach the
/// server and fail every token exchange of that client, on the request, with an error that names neither the client nor
/// the setting. A client exchanging tokens addressed to it with no location of its own exchanges none, which is a
/// configuration mistake rather than a policy. The issuer is the audience of every access token whose request named no
/// resource, so a client naming it as its location would be the resource server of all of them.
/// </remarks>
public sealed class CrossClientSubjectTokenExchangeCheck : ITenantsCheck
{
    /// <inheritdoc />
    public IEnumerable<TenantRefusal> Check(IReadOnlyCollection<TenantDefinition> tenants, OidcOptions options)
        => TenantRefusal.EachOf(tenants, tenant => tenant.Clients.SelectMany(client => Failures(tenant, client)));

    private static IEnumerable<string> Failures(TenantDefinition tenant, ClientInfo client)
    {
        if (!Enum.IsDefined(client.CrossClientSubjectTokenExchange))
        {
            yield return
                $"The client '{client.ClientId}' is configured with {nameof(ClientInfo.CrossClientSubjectTokenExchange)} " +
                $"'{client.CrossClientSubjectTokenExchange}', which is none of " +
                $"{string.Join(", ", Enum.GetNames<CrossClientSubjectTokenExchange>())}.";
        }

        if (client.CrossClientSubjectTokenExchange is CrossClientSubjectTokenExchange.AddressedToClient &&
            client.ResourceLocations is not { Length: > 0 })
        {
            yield return
                $"The client '{client.ClientId}' is configured with {nameof(ClientInfo.CrossClientSubjectTokenExchange)} " +
                $"'{nameof(CrossClientSubjectTokenExchange.AddressedToClient)}' and no " +
                $"{nameof(ClientInfo.ResourceLocations)}, so no token is addressed to it.";
        }

        if (client.ResourceLocations?.FirstOrDefault(location => tenant.IssuerIsNamedBy(location.OriginalString))
            is { } issuer)
        {
            yield return
                $"The client '{client.ClientId}' names the issuer '{issuer.OriginalString}' among its " +
                $"{nameof(ClientInfo.ResourceLocations)}, the audience of every access token whose request named no " +
                "resource.";
        }
    }
}
