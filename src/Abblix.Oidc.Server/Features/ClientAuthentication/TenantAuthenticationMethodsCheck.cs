// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Refuses a tenant whose security profile, together with the client authentication methods the server offers it,
/// admits no method at the token endpoint: no client of such a tenant could be issued a token, and its revocation
/// and introspection endpoints, which take their methods from the token endpoint's, would admit no caller either.
/// </summary>
/// <remarks>
/// The introspection endpoint alone admitting none is not refused: a tenant whose clients are all public calls it
/// for nothing.
/// </remarks>
/// <param name="serviceProvider">Resolves the client authenticator, which names the methods the server offers, when
/// a list is judged rather than when the check is built: the authenticator reads the server's settings, and the
/// settings are validated by the checks.</param>
internal sealed class TenantAuthenticationMethodsCheck(IServiceProvider serviceProvider) : ITenantsCheck
{
    /// <inheritdoc />
    public IEnumerable<TenantRefusal> Check(IReadOnlyCollection<TenantDefinition> tenants, OidcOptions options)
    {
        var offered = serviceProvider.GetRequiredService<IClientAuthenticator>()
            .ClientAuthenticationMethodsSupported
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        return
            from tenant in tenants
            where tenant.AdmittedAuthenticationMethods(offered).Length == 0
            select TenantRefusal.Of(tenant, RefusalOf(tenant, offered));
    }

    private static string RefusalOf(TenantDefinition tenant, string[] offered)
    {
        if (offered.Length == 0)
        {
            return $"Tenant '{tenant.Id}': the server offers no client authentication method at the token endpoint, so " +
                   "no client of the tenant could be issued a token.";
        }

        var reasons = offered.Select(method =>
            $"a client authenticating with {method} is refused: {tenant.WhyAuthenticationMethodRefused(method)}");

        return $"Tenant '{tenant.Id}' (security profile {tenant.DefaultSecurityProfile}) admits none of the client " +
               "authentication methods the server offers at the token endpoint, so no client of the tenant could be " +
               $"issued a token: {string.Join("; ", reasons)}.";
    }
}
