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
/// Fails at startup on a caller budget that would refuse everybody: a limit at or below zero, or a window of no
/// length.
/// </summary>
/// <remarks>
/// Both numbers reach <c>FixedWindowRateLimiterOptions</c>, which throws on them - but it is constructed the
/// first time a caller is counted, so without this the deployment starts, serves its metadata, and then answers
/// 500 to the first introspection request anyone makes. Refusing at startup puts the fault in front of whoever
/// wrote the number instead of whoever calls the endpoint.
/// </remarks>
public sealed class CallerRateLimitOptionsValidator : IValidateOptions<OidcOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        var rateLimit = options.CallerRateLimit;

        if (rateLimit.PermitLimit is <= 0)
        {
            return ValidateOptionsResult.Fail(
                $"{nameof(options.CallerRateLimit)}.{nameof(rateLimit.PermitLimit)} is {rateLimit.PermitLimit}, " +
                "so the introspection and revocation endpoints would refuse every request from every client. " +
                "Set it to the number of requests one client may make, or to null to apply no limit at all.");
        }

        if (rateLimit.PermitLimit.HasValue && rateLimit.Window <= TimeSpan.Zero)
        {
            return ValidateOptionsResult.Fail(
                $"{nameof(options.CallerRateLimit)}.{nameof(rateLimit.Window)} is {rateLimit.Window}, which is no " +
                "span of time to count requests over. Set it to how long the limit applies for, one second by " +
                "default.");
        }

        var failureLimit = options.AuthenticationFailureLimit;

        if (failureLimit.PermitLimit is <= 0)
        {
            return ValidateOptionsResult.Fail(
                $"{nameof(options.AuthenticationFailureLimit)}.{nameof(failureLimit.PermitLimit)} is " +
                $"{failureLimit.PermitLimit}, so no credential would be looked at anywhere and no client could " +
                "authenticate at all - not at the token endpoint, nor at any other. Set it to the number of " +
                "failures one source may make, or to null to count none.");
        }

        if (failureLimit.PermitLimit.HasValue && failureLimit.Window <= TimeSpan.Zero)
        {
            return ValidateOptionsResult.Fail(
                $"{nameof(options.AuthenticationFailureLimit)}.{nameof(failureLimit.Window)} is " +
                $"{failureLimit.Window}, which is no span of time to count failures over. Set it to how long the " +
                "limit applies for, one minute by default.");
        }

        return ValidateOptionsResult.Success;
    }
}
