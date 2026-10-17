// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using System.Net;
using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests;

/// <summary>
/// A server let run on an http issuer, for local development, is served over http: its endpoints do not send the
/// client to https, which such a server does not listen on.
/// </summary>
public sealed class HttpIssuerTests(HttpIssuerTests.HttpIssuerFactory factory, TestFactory httpsFactory)
    : IClassFixture<HttpIssuerTests.HttpIssuerFactory>, IClassFixture<TestFactory>
{
    /// <summary>
    /// A server whose issuer is https still sends a request over http to https.
    /// </summary>
    [Fact]
    public async Task Discovery_OfAnHttpsIssuer_ReachedOverHttp_IsRedirected()
    {
        using var client = httpsFactory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = HttpIssuerFactory.HttpAddress,
        });
        using var response = await client.GetAsync(
            "/.well-known/openid-configuration", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Equal(Uri.UriSchemeHttps, response.Headers.Location?.Scheme);
    }

    [Fact]
    public async Task Discovery_OfAnHttpIssuer_IsServedOverHttp()
    {
        // Not following redirects, or a redirect to https would be followed and answered there
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = HttpIssuerFactory.HttpAddress,
        });
        using var response = await client.GetAsync(
            "/.well-known/openid-configuration", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    /// <summary>
    /// The sample host with an http issuer let through, reached over http.
    /// </summary>
    public sealed class HttpIssuerFactory : TestFactory
    {
        [SuppressMessage("Minor Code Smell", "S1075",
            Justification = "In-memory TestServer base address; not a deployment URL.")]
        public static readonly Uri HttpAddress = new("http://localhost");

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.ConfigureTestServices(services =>
                services.AddSingleton<IPostConfigureOptions<OidcOptions>>(_ =>
                    new PostConfigureOptions<OidcOptions>(
                        Options.DefaultName,
                        options => options.AllowHttpIssuer = true)));
        }
    }
}
