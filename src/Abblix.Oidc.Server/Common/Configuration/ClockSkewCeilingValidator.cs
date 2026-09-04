// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Refuses a configured clock skew the validator would not honour, while the host is still starting.
/// </summary>
/// <remarks>
/// FAPI 2.0 Security Profile section 5.3.2.1: a server "shall reject JWTs with an <c>iat</c> or
/// <c>nbf</c> timestamp greater than 60 seconds in the future". The validator holds that bound
/// whatever a caller asks for, which closes the requirement but leaves a second problem: a
/// deployment could set five minutes, read the setting back, and believe it had five minutes in both
/// directions while getting sixty seconds in one of them.
///
/// A setting that is silently clamped is worse than one that is refused, because nothing ever says
/// so. This says so, at startup, where the operator is still looking - and it says which value and
/// which bound, so the answer is to edit the number rather than to go reading the validator.
/// </remarks>
public sealed class ClockSkewCeilingValidator : IValidateOptions<OidcOptions>
{
    /// <summary>
    /// The bound FAPI 2.0 section 5.3.2.1 puts on how far ahead a token may be dated. Note 3 gives
    /// the reason it exists at all: "to prevent implementations switching off iat and nbf checks
    /// completely".
    /// </summary>
    public static readonly TimeSpan Ceiling = TimeSpan.FromSeconds(60);

    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        var skew = options.JwtBearer.ClockSkew;

        if (skew < TimeSpan.Zero)
        {
            return ValidateOptionsResult.Fail(
                $"{nameof(OidcOptions.JwtBearer)}.{nameof(JwtBearerOptions.ClockSkew)} is {skew}, " +
                $"which refuses an assertion valid at the instant its request arrives instead of " +
                $"allowing for clock offset. Set a value between zero and {Ceiling}.");
        }

        if (Ceiling < skew)
        {
            return ValidateOptionsResult.Fail(
                $"{nameof(OidcOptions.JwtBearer)}.{nameof(JwtBearerOptions.ClockSkew)} is {skew}, " +
                $"above the {Ceiling} a token may be dated ahead of this server. The validator holds " +
                $"that bound regardless, so a larger value here would widen only the other " +
                $"direction while reading as though it widened both.");
        }

        return ValidateOptionsResult.Success;
    }
}
