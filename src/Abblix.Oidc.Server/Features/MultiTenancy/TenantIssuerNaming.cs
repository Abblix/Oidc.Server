// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// The single owner of the answer whether a value a JWT carries in its <c>aud</c> or <c>iss</c> claim names a tenant's
/// issuer identifier. Every check that accepts the issuer as an audience - a request object, a login_hint_token, a
/// client assertion, a JWT bearer grant, a signed CIBA request, a token this server issued - and every check that
/// takes a token for one this server issued asks it, so none of them can accept a spelling another refuses. The
/// tokens and responses that carry the issuer take its spelling from here too, so what this server writes is what it
/// accepts.
/// <para>
/// Two comparisons deliberately stay outside, since each only refuses - a wider match refuses more - while this owner's
/// answer accepts, so neither may be folded into it. <see cref="TenantIssuers.Same"/> reads scheme and host without
/// regard to case to answer whether an issuer of a token another party wrote is one of this server's tenants, for the
/// JWT bearer grant and software statements. A client identifier metadata document's URL is refused where it equals
/// the issuer as written, taken from here, or normalized as well.
/// </para>
/// </summary>
/// <remarks>
/// One spelling, the identifier exactly as written, which is the one discovery publishes as <c>issuer</c> and the one
/// this server writes into <c>iss</c>, compared by the Simple String Comparison of RFC 3986 section 6.2.1, as RFC 10070
/// section 4 has audiences compared. A normalized spelling is not accepted beside it, unlike the endpoint URLs
/// <see cref="TenantEndpointAddresses.AcceptedSpellings(TenantDefinition, Uri)"/> lists: discovery publishes an
/// endpoint normalized while the issuer writes its authority, so an endpoint has two spellings a client may have
/// read, while the issuer has one.
/// </remarks>
internal static class TenantIssuerNaming
{
    /// <summary>
    /// The value that names <paramref name="tenant"/>'s issuer identifier: the identifier exactly as written.
    /// </summary>
    /// <param name="tenant">The tenant whose issuer identifier is named.</param>
    public static string IssuerAsWritten(this TenantDefinition tenant) => tenant.Issuer.OriginalString;

    /// <summary>
    /// Answers whether <paramref name="value"/> names <paramref name="tenant"/>'s issuer identifier.
    /// </summary>
    /// <param name="tenant">The tenant whose issuer identifier is named.</param>
    /// <param name="value">A value of the token's <c>aud</c> or <c>iss</c> claim, or null where it carries none.</param>
    public static bool IssuerIsNamedBy(this TenantDefinition tenant, string? value)
        => string.Equals(value, tenant.IssuerAsWritten(), StringComparison.Ordinal);

    /// <summary>
    /// Answers whether one of <paramref name="values"/> names <paramref name="tenant"/>'s issuer identifier.
    /// </summary>
    /// <param name="tenant">The tenant whose issuer identifier is named.</param>
    /// <param name="values">The values of the token's <c>aud</c> claim.</param>
    public static bool IssuerIsNamedByAny(this TenantDefinition tenant, IEnumerable<string> values)
        => values.Any(tenant.IssuerIsNamedBy);
}
