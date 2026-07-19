// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Endpoints.DeviceAuthorization;

/// <summary>
/// Fails loudly the first time <see cref="OidcOptions"/> is resolved when the device authorization endpoint is enabled
/// but its settings are absent, instead of letting the contradiction surface as an unhandled HTTP 500 on the first
/// request. The endpoint is off in the default <see cref="OidcEndpoints.Base"/> set and is turned on only by an
/// explicit <c>AddDeviceAuthorization()</c> opt-in (or a host that sets the
/// <see cref="OidcEndpoints.DeviceAuthorization"/> flag itself), yet <see cref="OidcOptions.DeviceAuthorization"/> has
/// no default — so a host that enables it without configuring it has an internally inconsistent configuration this
/// validator turns into a clear startup error. A no-op when the endpoint is disabled or the settings are present.
/// </summary>
public class DeviceAuthorizationOptionsValidator : IValidateOptions<OidcOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
        => options.EnabledEndpoints.HasFlag(OidcEndpoints.DeviceAuthorization) && options.DeviceAuthorization is null
            ? ValidateOptionsResult.Fail(
                $"The device authorization endpoint is enabled in {nameof(OidcOptions.EnabledEndpoints)} but " +
                $"{nameof(OidcOptions)}.{nameof(OidcOptions.DeviceAuthorization)} is not configured. Supply it " +
                "(VerificationUri, CodeLifetime, PollingInterval, ...) or clear " +
                $"{nameof(OidcEndpoints.DeviceAuthorization)} from {nameof(OidcOptions.EnabledEndpoints)}.")
            : ValidateOptionsResult.Success;
}
