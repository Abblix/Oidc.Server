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
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.MinimalApi;

namespace Abblix.DocSamples.Samples;

/// <summary>
/// The compiled copy of the quick-start in the Minimal API package's README.
/// </summary>
/// <remarks>
/// The imports above the ambient markers are the ones the README itself shows; the two inside them are
/// what a project created from the web template gets without asking. The release workflow builds this
/// block as the Program.cs of a new web project, so it is the reader's paste that is started there.
/// </remarks>
internal static class MinimalApiQuickstartSample
{
    internal static void Configure(string[] args)
    {
        // <sample>
        var builder = WebApplication.CreateBuilder(args);

        // Grants every client everything it asks for, which suits only clients of your own;
        // to ask the end user for consent, register your own IUserConsentsProvider instead
        builder.Services.AddConsentGrantedForEveryClient();

        // The server serves tenants; a host serving one issuer declares one, with its clients, scopes and signing keys
        builder.Services.AddOidcServices(options => options.Tenants.Add(new TenantDefinition
        {
            Id = "main",
            // The address the app is served on, read from the "Issuer" setting
            Issuer = new Uri(builder.Configuration["Issuer"]
                ?? throw new InvalidOperationException("Set Issuer to the address the app is served on")),
            LoginUri = new Uri("/Auth/Login", UriKind.Relative),
            SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
        }));

        var app = builder.Build();

        app.UseCors();

        app.MapOidcEndpoints();

        app.Run();
        // </sample>
    }
}
