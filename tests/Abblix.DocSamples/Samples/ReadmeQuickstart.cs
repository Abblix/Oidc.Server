// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

// <ambient>
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
// </ambient>
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.MinimalApi;

namespace Abblix.DocSamples.Samples;

/// <summary>
/// The compiled copy of the quick-start in the repository's README.
/// </summary>
/// <remarks>
/// The imports above the ambient markers are the ones the README itself shows; the two inside them are
/// what a project created from the web template gets without asking, and <c>ReadmeSampleTests</c> holds
/// that region to the template's own list. A copy that quietly imports something the reader has not got
/// would compile here and fail for them, which is exactly how the stale quick-start survived.
/// </remarks>
internal static class ReadmeQuickstartSample
{
    internal static void Configure(string[] args)
    {
        // <sample>
        var builder = WebApplication.CreateBuilder(args);

        // Grants every client everything it asks for, which suits only clients of your own;
        // to ask the end user for consent, register your own IUserConsentsProvider instead
        builder.Services.AddConsentGrantedForEveryClient();

        // Turn your ASP.NET Core app into an OpenID Connect provider serving one issuer
        builder.Services.AddOidcServices(options => options.Tenants.Add(new TenantDefinition
        {
            Id = "main",
            // The address the app is served on: a request to any other reaches no tenant and is answered 404
            Issuer = new Uri("https://auth.example.com"),
            LoginUri = new Uri("/Auth/Login", UriKind.Relative),
            SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
        }));

        var app = builder.Build();

        // Resolve each request to the tenant its address names, before routing
        app.UseMultiTenancy();
        app.MapOidcEndpoints();
        app.Run();
        // </sample>
    }
}
