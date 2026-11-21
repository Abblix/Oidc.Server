// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;

/// <summary>
/// Starts a host whose confidential client registered a back-channel logout URI, so the ID tokens it receives name
/// their session: a revocation of that session reaches them, an exchange accepts them, and a logout they hint at
/// needs no confirmation.
/// </summary>
public static class SessionLogoutHostExtensions
{
    private static readonly Uri BackChannelLogoutUri = new("https://client.example.com/back-channel-logout");

    /// <summary>
    /// A host of its own whose confidential client uses the session at logout.
    /// </summary>
    /// <param name="factory">The shared host the variant is built from.</param>
    /// <param name="configure">Options the test turns on beside it, if any.</param>
    public static WebApplicationFactory<Program> WithSessionLogout(
        this WebApplicationFactory<Program> factory,
        Action<OidcOptions>? configure = null)
        => factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            services.PostConfigure<TestTenantSettings>(tenant =>
            {
                foreach (var clientInfo in tenant.Clients)
                {
                    if (clientInfo.ClientId == TestConstants.ConfidentialClientId)
                        clientInfo.BackChannelLogout = new BackChannelLogoutOptions(BackChannelLogoutUri);
                }
            });

            if (configure != null)
                services.Configure(configure);
        }));
}
