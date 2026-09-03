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
/// Refuses a clock-offset tolerance no specification allows, while the host is still starting.
/// </summary>
/// <remarks>
/// FAPI 2.0 Security Profile section 5.3.2.1 states both halves of this: a server "shall accept JWTs
/// with an <c>iat</c> or <c>nbf</c> timestamp between 0 and 10 seconds in the future but shall reject
/// JWTs with an <c>iat</c> or <c>nbf</c> timestamp greater than 60 seconds in the future". The upper
/// half is the reason this type exists. A tolerance is a window in which a token minted for the
/// future is honoured, so an unbounded one turns the freshness check off by configuration - and it
/// does so silently, with every document still saying the server performs it.
///
/// A negative value is refused for the opposite reason: it would narrow the check past exactness,
/// refusing a token issued at the very instant the request arrives, which reads as a mysterious
/// intermittent failure rather than as a setting.
/// </remarks>
public sealed class ClockOffsetToleranceValidator : IValidateOptions<OidcOptions>
{
    /// <summary>
    /// The largest tolerance FAPI 2.0 section 5.3.2.1 permits.
    /// </summary>
    public static readonly TimeSpan Ceiling = TimeSpan.FromSeconds(60);

    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        var tolerance = options.ClockOffsetTolerance;

        if (tolerance < TimeSpan.Zero)
        {
            return ValidateOptionsResult.Fail(
                $"{nameof(OidcOptions.ClockOffsetTolerance)} is {tolerance}, which refuses a token " +
                $"issued at the instant its request arrives instead of allowing for clock offset. " +
                $"Set a value between zero and {Ceiling}.");
        }

        if (tolerance > Ceiling)
        {
            return ValidateOptionsResult.Fail(
                $"{nameof(OidcOptions.ClockOffsetTolerance)} is {tolerance}, above the {Ceiling} " +
                $"ceiling. A wider window accepts a token minted that far ahead, which is the " +
                $"freshness check turned off by configuration rather than a tolerance.");
        }

        return ValidateOptionsResult.Success;
    }
}
