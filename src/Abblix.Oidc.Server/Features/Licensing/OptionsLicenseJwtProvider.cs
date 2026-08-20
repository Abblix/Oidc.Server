// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.Licensing;

/// <summary>
/// An <see cref="ILicenseJwtProvider"/> backed by the <see cref="OidcOptions.LicenseJwt"/> value
/// resolved through the options pattern.
/// </summary>
/// <remarks>
/// Returns a single-element async sequence containing the configured license JWT, or null when no
/// license JWT has been configured. Used as the default provider when the host configures the
/// license through standard configuration sources (appsettings, environment variables, etc.).
/// </remarks>
public class OptionsLicenseJwtProvider(IOptions<OidcOptions> options) : ILicenseJwtProvider
{
    /// <summary>
    /// Asynchronously retrieves the license JWT from the OIDC service configuration.
    /// </summary>
    /// <returns>A task representing the asynchronous operation, which upon completion contains the license JWT used for
    /// validating the configuration and licensing terms of the OIDC service.</returns>
    public IAsyncEnumerable<string>? GetLicenseJwtAsync()
    {
        var licenseJwt = options.Value.LicenseJwt;
        return licenseJwt != null ? new[] { licenseJwt }.ToAsyncEnumerable() : null;
    }
}
