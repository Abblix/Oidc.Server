// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.DeviceAuthorization;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Endpoints.DeviceAuthorization;

/// <summary>
/// Fails loudly the first time <see cref="OidcOptions"/> is resolved when the device authorization endpoint is enabled
/// but its settings are absent or leave a brute-force limit unable to fire, instead of letting the contradiction
/// surface as an unhandled HTTP 500 on the first request. The endpoint is off in the default
/// <see cref="OidcEndpoints.Base"/> set and is turned on only by an
/// explicit <c>AddDeviceAuthorization()</c> opt-in (or a host that sets the
/// <see cref="OidcEndpoints.DeviceAuthorization"/> flag itself), yet <see cref="OidcOptions.DeviceAuthorization"/> has
/// no default - so a host that enables it without configuring it has an internally inconsistent configuration this
/// validator turns into a clear startup error. A no-op when the endpoint is disabled or the settings are sound.
/// <para>
/// The rate-limit checks are here for the same reason and not as defensive programming: each of those values reads
/// as a stricter setting and acts as no setting at all, so the deployment loses the defense a short user code has
/// and nothing says so. A limit that cannot fire is indistinguishable at runtime from a limit nobody has reached
/// yet. RFC 8628 section 5.1 recommends the limiting in lower case and puts its capitalised SHOULD on the code
/// having enough entropy "when combined with rate-limiting", so a limit switched off silently also takes that
/// clause's other half with it.
/// </para>
/// </summary>
public class DeviceAuthorizationOptionsValidator : IValidateOptions<OidcOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        if (!options.EnabledEndpoints.HasFlag(OidcEndpoints.DeviceAuthorization))
            return ValidateOptionsResult.Success;

        if (options.DeviceAuthorization is not { } deviceAuthorization)
            return ValidateOptionsResult.Fail(
                $"The device authorization endpoint is enabled in {nameof(OidcOptions.EnabledEndpoints)} but " +
                $"{nameof(OidcOptions)}.{nameof(OidcOptions.DeviceAuthorization)} is not configured. Supply it " +
                "(VerificationUri, CodeLifetime, PollingInterval, ...) or clear " +
                $"{nameof(OidcEndpoints.DeviceAuthorization)} from {nameof(OidcOptions.EnabledEndpoints)}.");

        if (deviceAuthorization.MaxUserCodeAttempts < 1 ||
            UserCodeRateLimiter.AttemptLadderLength < deviceAuthorization.MaxUserCodeAttempts)
            return ValidateOptionsResult.Fail(
                $"{nameof(DeviceAuthorizationOptions.MaxUserCodeAttempts)} is " +
                $"{deviceAuthorization.MaxUserCodeAttempts}, which is not a number of attempts a code can " +
                $"have: below 1 no code could ever be verified, and above " +
                $"{UserCodeRateLimiter.AttemptLadderLength} the limit is never reached because that is how " +
                "many attempts against one code are recorded, so nothing but expiry would stop guessing. " +
                $"Choose a value between 1 and {UserCodeRateLimiter.AttemptLadderLength}.");

        if (deviceAuthorization.MaxFailuresBeforeBackoff < 1 ||
            UserCodeRateLimiter.AttemptLadderLength < deviceAuthorization.MaxFailuresBeforeBackoff)
            return ValidateOptionsResult.Fail(
                $"{nameof(DeviceAuthorizationOptions.MaxFailuresBeforeBackoff)} is " +
                $"{deviceAuthorization.MaxFailuresBeforeBackoff}, and the backoff it starts could never begin: " +
                $"attempts against one user code are recorded up to {UserCodeRateLimiter.AttemptLadderLength}, and " +
                "a value below 1 describes a pause starting before any attempt has been made. Choose a value " +
                $"between 1 and {UserCodeRateLimiter.AttemptLadderLength}.");

        if (deviceAuthorization.MaxFailedAttemptsPerWindow < 1)
            return ValidateOptionsResult.Fail(
                $"{nameof(DeviceAuthorizationOptions.MaxFailedAttemptsPerWindow)} is " +
                $"{deviceAuthorization.MaxFailedAttemptsPerWindow}, so the server would refuse every " +
                "verification from the first failure of every window - and it is the only limit that bounds " +
                "a guessing search spread across addresses, so switching it off that way removes the bound " +
                "rather than tightening it. Choose 1 or more.");

        if (deviceAuthorization.MaxIpFailuresPerMinute < 1)
            return ValidateOptionsResult.Fail(
                $"{nameof(DeviceAuthorizationOptions.MaxIpFailuresPerMinute)} is " +
                $"{deviceAuthorization.MaxIpFailuresPerMinute}, so the per-address cap can never be reached and " +
                "failures from one source are not limited at all. Choose 1 or more.");

        if (deviceAuthorization.RateLimitWindow <= TimeSpan.Zero)
            return ValidateOptionsResult.Fail(
                $"{nameof(DeviceAuthorizationOptions.RateLimitWindow)} is " +
                $"{deviceAuthorization.RateLimitWindow}, and attempts are counted per window, so a window " +
                "of no length counts nothing. Choose a positive duration.");

        if (deviceAuthorization.IpRateLimitStateExpiration < deviceAuthorization.RateLimitWindow)
            return ValidateOptionsResult.Fail(
                $"{nameof(DeviceAuthorizationOptions.IpRateLimitStateExpiration)} " +
                $"({deviceAuthorization.IpRateLimitStateExpiration}) is shorter than " +
                $"{nameof(DeviceAuthorizationOptions.RateLimitWindow)} " +
                $"({deviceAuthorization.RateLimitWindow}), so recorded attempts are dropped while their own " +
                "window is still running and the cap is reached later than configured, or never. Keep the " +
                "retention at least as long as the window.");

        return ValidateOptionsResult.Success;
    }
}
