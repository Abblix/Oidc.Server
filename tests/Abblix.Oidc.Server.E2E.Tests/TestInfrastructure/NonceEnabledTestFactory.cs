// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;

/// <summary>
/// Variant of <see cref="Tests.TestFactory"/> that flips on the RFC 9449 section 8 nonce
/// requirement at both the token endpoint and the UserInfo endpoint. Hosted under a
/// separate xunit collection so the singleton <see cref="WebApplicationFactory{TEntryPoint}"/>
/// inside this factory never shares state with the default flow tests - toggling
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
