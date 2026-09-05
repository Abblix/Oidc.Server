// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Mvc.Conventions;

/// <summary>
/// Registers <see cref="EnabledByConvention"/> with MVC so that controller and action methods
/// decorated with <c>[EnabledBy]</c> are filtered out of the application model when the corresponding
/// OIDC endpoint flag is disabled in <see cref="OidcOptions.EnabledEndpoints"/>.
/// Runs as a post-configuration step on <see cref="MvcOptions"/>, after the host-supplied configuration.
/// </summary>
internal class ConfigureEndpointConventions(IOptions<OidcOptions> oidcOptions)
    : IPostConfigureOptions<MvcOptions>
{
    /// <summary>
    /// Adds the <see cref="EnabledByConvention"/> instance to the MVC application model conventions.
    /// </summary>
    public void PostConfigure(string? name, MvcOptions options)
    {
        options.Conventions.Add(new EnabledByConvention(oidcOptions));
    }
}
