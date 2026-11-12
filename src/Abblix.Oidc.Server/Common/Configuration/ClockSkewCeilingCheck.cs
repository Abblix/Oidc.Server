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
/// The two settings it reads fail differently above the bound. The tolerance for other parties' assertions is held
/// to the bound by the validator whatever is configured, so there the refusal exists because a setting silently
/// clamped is worse than one refused: a deployment could read the setting back and believe a number the validator
/// was cutting down. The drift between this server's own instances is applied as configured, so above the bound
/// it would let a token this server issued be accepted dated further ahead than the profile allows, and this check
/// is what keeps that from happening.
/// </para>
/// </remarks>
public sealed class ClockSkewCeilingCheck : ITenantsCheck
{
    /// <inheritdoc />
    public IEnumerable<TenantRefusal> Check(IReadOnlyCollection<TenantDefinition> tenants, OidcOptions options)
    {
        // The drift between this server's own instances is always set, since it has a default. Of the tolerance for
        // other parties' assertions only a value this deployment set is worth refusing: absence means it asked the
        // profile to decide, and what the profile decides is by construction what the profile allows
        var settings = new List<(string Name, TimeSpan Value, string Consequence)>
        {
            ($"{nameof(OidcOptions)}.{nameof(OidcOptions.ClockSkew)}", options.ClockSkew,
                "It is applied as configured, so a token this server issued would be accepted dated further ahead " +
                "than the profile allows."),
        };
        if (options.JwtBearer.ClockSkew is { } skew && skew >= TimeSpan.Zero)
        {
            settings.Add((
                $"{nameof(OidcOptions)}.{nameof(OidcOptions.JwtBearer)}.{nameof(JwtBearerOptions.ClockSkew)}", skew,
                "The value is held to that bound in both directions whatever is configured, so a larger one widens " +
                "nothing while reading as though it did."));
        }

        return TenantRefusal.EachOf(
            tenants,
            tenant => settings.SelectMany(setting => Failures(tenant, setting.Name, setting.Value, setting.Consequence)));
    }

    private static IEnumerable<string> Failures(TenantDefinition tenant, string setting, TimeSpan skew, string consequence)
    {
        // A profile that names no bound leaves the question to RFC 7523, which does not answer it, and a profile
        // the enumeration does not define is refused by the check of the profiles
        if (!Enum.IsDefined(tenant.DefaultSecurityProfile) ||
            SecurityProfileRequirements.Resolve(tenant.DefaultSecurityProfile).MaxClockSkew is not { } ceiling ||
            skew <= ceiling)
        {
            yield break;
        }

        yield return $"{setting} is {skew}, above the {ceiling} the {tenant.DefaultSecurityProfile} profile allows. {consequence}";
    }
}
