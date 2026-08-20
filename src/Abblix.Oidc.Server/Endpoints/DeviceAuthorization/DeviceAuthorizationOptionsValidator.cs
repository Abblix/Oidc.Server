// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Endpoints.DeviceAuthorization;

/// <summary>
/// Fails loudly the first time <see cref="OidcOptions"/> is resolved when the device authorization endpoint is enabled
/// but its settings are absent, instead of letting the contradiction surface as an unhandled HTTP 500 on the first
/// request. The endpoint is off in the default <see cref="OidcEndpoints.Base"/> set and is turned on only by an
/// explicit <c>AddDeviceAuthorization()</c> opt-in (or a host that sets the
/// <see cref="OidcEndpoints.DeviceAuthorization"/> flag itself), yet <see cref="OidcOptions.DeviceAuthorization"/> has
/// no default - so a host that enables it without configuring it has an internally inconsistent configuration this
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
