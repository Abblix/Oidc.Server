// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Options;
using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Refuses a configured clock skew the validator would not honour, while the host is still starting -
/// and only where a profile puts a bound on it at all.
/// </summary>
/// <remarks>
/// FAPI 2.0 Security Profile section 5.3.2.1: a server held to it "shall reject JWTs with an
/// <c>iat</c> or <c>nbf</c> timestamp greater than 60 seconds in the future". RFC 7523 Section 3,
/// which governs a bearer assertion outside that profile, names no bound, so a deployment not held
/// to a profile may legitimately allow minutes and this guard says nothing to it.
///
/// Where a bound does apply, the validator holds it whatever is configured - so this guard is not
/// what makes the requirement true. It exists because a setting that is silently clamped is worse
/// than one that is refused: a deployment could set a window, read the setting back, and believe a
/// number the validator was cutting down. This says which value and which bound, at startup, where
/// the operator is still looking.
/// </remarks>
public sealed class ClockSkewCeilingValidator : IValidateOptions<OidcOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        // Only a value this deployment set is worth refusing. Absence means it asked the profile to
        // decide, and what the profile decides is by construction what the profile allows - refusing
        // that would fail every deployment over a number nobody chose.
        if (options.JwtBearer.ClockSkew is not { } skew)
            return ValidateOptionsResult.Success;

        if (skew < TimeSpan.Zero)
        {
            return ValidateOptionsResult.Fail(
                $"{nameof(OidcOptions.JwtBearer)}.{nameof(JwtBearerOptions.ClockSkew)} is {skew}, " +
                $"which refuses an assertion valid at the instant its request arrives instead of " +
                $"allowing for clock offset. Set a value of zero or more.");
        }

        // A profile that names no bound leaves the question to RFC 7523, which does not answer it.
        if (SecurityProfileRequirements.Resolve(options.DefaultSecurityProfile).MaxClockSkew
                is not { } ceiling)
        {
            return ValidateOptionsResult.Success;
        }

        if (ceiling < skew)
        {
            return ValidateOptionsResult.Fail(
                $"{nameof(OidcOptions.JwtBearer)}.{nameof(JwtBearerOptions.ClockSkew)} is {skew}, " +
                $"above the {ceiling} the {options.DefaultSecurityProfile} profile allows a token to " +
                $"be dated ahead of this server. The validator holds that bound regardless, so a " +
                $"larger value here would widen only the other direction while reading as though it " +
                $"widened both.");
        }

        return ValidateOptionsResult.Success;
    }
}
