// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

// The feature is marked experimental for its consumers; the README says how a project accepts that.
#pragma warning disable ABXMT001

// <ambient>
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
// </ambient>
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Oidc.Server.SharedSignals;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SharedSignals.Infrastructure;
using Abblix.SharedSignals.Transmitter;

namespace Abblix.DocSamples.Samples;

/// <summary>
/// The compiled copy of the sample in the README of Abblix.Oidc.Server.SharedSignals.
/// </summary>
internal static class SharedSignalsMultiTenancySample
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Minor Code Smell", "S1075",
        Justification = "The README shows the addresses a reader replaces with their own.")]
    internal static void Configure(string[] args)
    {
        // <sample>
        var builder = WebApplication.CreateBuilder(args);

        builder.Services.AddSecurityEvents();
        builder.Services.AddSharedSignalsTransmitter(new SharedSignalsTransmitterOptions
        {
            Issuer = "https://idp.example.com",
            JwksUri = new Uri("https://idp.example.com/.well-known/jwks"),
            EventsSupported = ["https://schemas.openid.net/secevent/caep/event-type/session-revoked"],
        });

        builder.Services.AddOidcServices(_ => { });
        builder.Services
            .AddMultiTenancy(options => options.Tenants.Add(new TenantDefinition
            {
                Id = "acme",
                Issuer = "https://idp.example.com/acme",
                SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)],
            }))
            .AddSharedSignals();
        // </sample>
    }
}
