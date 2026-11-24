// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Which of the client authentication methods the server offers a tenant admits a client authenticating with at the
/// token endpoint, the revocation and introspection endpoints taking theirs from that list.
/// </summary>
/// <remarks>
/// FAPI 2.0 Security Profile section 5.3.2.1 and FAPI 1.0 Part 2 section 5.2.2 admit mutual TLS and the private key
/// JWT alone, and refuse a public client. The tenant's profile binds every client it serves, which is refused where it
/// authenticates by the same rule, so a method it refuses is one no endpoint of the tenant authenticates a client
/// with. A tenant listing no certificate authority for tls_client_auth serves no client with it either (RFC 8705
/// section 2.1).
/// </remarks>
internal static class TenantClientAuthenticationMethods
{
    /// <summary>
    /// The methods of <paramref name="methods"/> <paramref name="tenant"/> admits a client authenticating with.
    /// </summary>
    /// <param name="tenant">The tenant asked about.</param>
    /// <param name="methods">The methods the server authenticates clients with.</param>
    public static string[] Admitted(TenantDefinition tenant, IEnumerable<string> methods)
    {
        var profile = SecurityProfileRequirements.For(tenant, client: null);
        return methods.Where(method => WhyRefused(tenant, profile, method) is null).ToArray();
    }

    /// <summary>
    /// Why <paramref name="tenant"/> admits no client authenticating with <paramref name="method"/>, or null where it
    /// admits one.
    /// </summary>
    /// <param name="tenant">The tenant asked about.</param>
    /// <param name="method">The client authentication method.</param>
    public static string? WhyRefused(TenantDefinition tenant, string method)
        => WhyRefused(tenant, SecurityProfileRequirements.For(tenant, client: null), method);

    /// <summary>
    /// Why <paramref name="tenant"/>, held to <paramref name="profile"/>, admits no client authenticating with
    /// <paramref name="method"/>, or null where it admits one.
    /// </summary>
    /// <param name="tenant">The tenant asked about.</param>
    /// <param name="profile">The control bundle of the tenant's own security profile.</param>
    /// <param name="method">The client authentication method.</param>
    public static string? WhyRefused(TenantDefinition tenant, SecurityProfileRequirements profile, string method)
    {
        var violations = SecurityProfileConsistency.FindAuthenticationMethodViolations(method, profile);
        if (violations.Count > 0)
            return string.Join("; ", violations);

        if (!TlsClientAuthCertificateAuthorities.Serve(tenant, method))
        {
            return $"the tenant lists no certificate authority in " +
                   $"{nameof(TenantDefinition)}.{nameof(TenantDefinition.TlsClientAuthCertificateAuthorities)}, as " +
                   "base64-encoded DER certificates, to validate a client certificate against";
        }

        return null;
    }
}
