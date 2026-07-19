// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/Oidc.Server. All development and modifications
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
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;

/// <summary>
/// Variant of <see cref="Tests.TestFactory"/> that flips on the RFC 9449 §8 nonce
/// requirement at both the token endpoint and the UserInfo endpoint. Hosted under a
/// separate xunit collection so the singleton <see cref="WebApplicationFactory{TEntryPoint}"/>
/// inside this factory never shares state with the default flow tests — toggling
/// <c>OidcOptions.DPoP.Nonce.RequireAtTokenEndpoint</c> globally would otherwise
/// cascade unrelated tests into the nonce challenge loop.
/// </summary>
public sealed class NonceEnabledTestFactory : TestFactory
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);

        builder.ConfigureTestServices(services =>
        {
            services.AddSingleton<IPostConfigureOptions<OidcOptions>>(_ =>
                new PostConfigureOptions<OidcOptions>(
                    Options.DefaultName,
                    options =>
                    {
                        options.DPoP.Nonce.RequireAtTokenEndpoint = true;
                        options.DPoP.Nonce.RequireAtUserInfoEndpoint = true;
                    }));
        });
    }
}
