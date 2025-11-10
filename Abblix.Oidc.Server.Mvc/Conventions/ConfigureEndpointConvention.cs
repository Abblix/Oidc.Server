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
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Mvc.Conventions;

/// <summary>
/// Post-configures MVC options to add the EnabledBy convention.
/// </summary>
internal class ConfigureEndpointConvention(IOptions<OidcOptions> oidcOptions)
    : IPostConfigureOptions<MvcOptions>
{
    public void PostConfigure(string? name, MvcOptions options)
    {
        options.Conventions.Add(new EnabledByConvention(oidcOptions));
    }
}
