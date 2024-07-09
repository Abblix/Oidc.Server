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

namespace Abblix.Oidc.Server.Features.Licensing;

public class OptionsLicenseJwtProvider : ILicenseJwtProvider
{
    /// <summary>
    /// Initializes a new instance of the <see cref="OptionsLicenseJwtProvider"/> class.
    /// </summary>
    /// <param name="options">The OIDC options containing the license JWT.</param>
    public OptionsLicenseJwtProvider(IOptions<OidcOptions> options)
    {
        _options = options;
    }

    private readonly IOptions<OidcOptions> _options;

    /// <summary>
    /// Asynchronously retrieves the license JWT from the OIDC service configuration.
    /// </summary>
    /// <returns>A task representing the asynchronous operation, which upon completion contains the license JWT used for
    /// validating the configuration and licensing terms of the OIDC service.</returns>
    public IAsyncEnumerable<string>? GetLicenseJwtAsync()
    {
        var licenseJwt = _options.Value.LicenseJwt;
        return licenseJwt != null ? new[] { licenseJwt }.ToAsyncEnumerable() : null;
    }
}
