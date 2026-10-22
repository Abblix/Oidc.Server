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
/// Refuses a tenant whose security profile bounds the clock skew below the one the server's settings allow.
/// </summary>
/// <remarks>
/// FAPI 2.0 Security Profile section 5.3.2.1: a server held to it "shall reject JWTs with an <c>iat</c> or
/// <c>nbf</c> timestamp greater than 60 seconds in the future". RFC 7523 Section 3, which governs a bearer assertion
/// outside that profile, names no bound, so a tenant not held to a profile may legitimately allow minutes and this
/// check says nothing to it.
/// <para>
/// Where a bound does apply, the validator holds it whatever is configured - so this check is not what makes the
/// requirement true. It exists because a setting that is silently clamped is worse than one that is refused: a
/// deployment could set a window, read the setting back, and believe a number the validator was cutting down.
/// </para>
/// </remarks>
public sealed class ClockSkewCeilingCheck : ITenantsCheck
{
    /// <inheritdoc />
    public IEnumerable<TenantRefusal> Check(IReadOnlyCollection<TenantDefinition> tenants, OidcOptions options)
        // Only a value this deployment set is worth refusing. Absence means it asked the profile to decide, and what
        // the profile decides is by construction what the profile allows
        => options.JwtBearer.ClockSkew is { } skew && skew >= TimeSpan.Zero
            ? TenantRefusal.EachOf(tenants, tenant => Failures(tenant, skew))
            : [];

    private static IEnumerable<string> Failures(TenantDefinition tenant, TimeSpan skew)
    {
        // A profile that names no bound leaves the question to RFC 7523, which does not answer it, and a profile
        // the enumeration does not define is refused by the check of the profiles
        if (!Enum.IsDefined(tenant.DefaultSecurityProfile) ||
            SecurityProfileRequirements.Resolve(tenant.DefaultSecurityProfile).MaxClockSkew is not { } ceiling ||
            skew <= ceiling)
        {
            yield break;
        }

        yield return
            $"{nameof(OidcOptions.JwtBearer)}.{nameof(JwtBearerOptions.ClockSkew)} is {skew}, above the {ceiling} " +
            $"the {tenant.DefaultSecurityProfile} profile allows. The value is held to that bound in both directions " +
            "whatever is configured, so a larger one widens nothing while reading as though it did.";
    }
}
