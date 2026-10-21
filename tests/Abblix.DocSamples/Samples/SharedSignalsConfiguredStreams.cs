// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server


// <ambient>
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
// </ambient>
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Oidc.Server.SharedSignals;
using Abblix.SharedSignals.Transmitter;

namespace Abblix.DocSamples.Samples;

/// <summary>
/// The compiled copy of the sample in the README of Abblix.Oidc.Server.SharedSignals that declares a tenant's streams.
/// </summary>
internal static class SharedSignalsConfiguredStreamsSample
{
    internal static void Configure(WebApplicationBuilder builder, TenantDefinition acme)
    {
        // <sample>
        builder.Services
            .AddOidcServices(options => options.Tenants.Add(acme))
            .AddSharedSignals()
            .AddConfiguredStreams("acme", builder.Configuration.GetSection("Acme:Streams").Get<ConfiguredStream[]>() ?? []);
        // </sample>
    }
}
