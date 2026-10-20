// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Reflection;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features;
using Abblix.Jwt;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.SharedSignals;
using Abblix.SecurityEvents.Infrastructure;
using SecurityEventsRegistration = Abblix.SecurityEvents.Infrastructure.ServiceCollectionExtensions;
using Abblix.SharedSignals.Infrastructure;
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;
using Abblix.Oidc.Server.Features.Consents;

#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// Every check of a server setting is registered by the server's own wiring, so a check written but never registered -
/// which every test calling it directly still passes - fails here instead of letting a deployment start with settings
/// it was written to refuse.
/// </summary>
/// <remarks>
/// The checks are found in the compiled packages, whatever settings type they judge, so a check added later is held
/// here without anybody extending a list. The wiring is the full server with each feature a host turns on by a call of
/// its own: backchannel authentication, device authorization, pairwise subject identifiers, a key custodian and a key
/// ring sealed to it, a Shared Signals transmitter, and multi-tenancy with Shared Signals on top of it.
/// </remarks>
public class SettingsChecksAreRegisteredTests
{
    private static readonly Assembly[] Packages =
    [
        typeof(JsonWebKey).Assembly,
        typeof(OidcOptions).Assembly,
        typeof(SharedSignalsTransmitterOptions).Assembly,
        typeof(SecurityEventsRegistration).Assembly,
        typeof(MultiTenancyExtensions).Assembly,
        typeof(SharedSignalsMultiTenancyExtensions).Assembly,
    ];

    [Fact]
    public void EveryCheckOfAServerSetting_IsRegisteredByTheServer()
    {
        var checks = Packages
            .SelectMany(package => package.GetTypes())
            .Where(type => type is { IsAbstract: false, IsInterface: false } && type.GetInterfaces().Any(IsSettingsCheck))
            .ToHashSet();
        Assert.Contains(typeof(ClockSkewCeilingValidator), checks);

        var services = new ServiceCollection();
        services.AddBackChannelAuthentication();
        services.AddDeviceAuthorization();
        services.AddPairwiseSubjectIdentifiers();
        services.AddConsentGrantedForEveryClient();
        services.AddOidcCore((_, _) => { });
        services.RequireKeyPlacement();
        services.AddKeyRing(new MintedKeys { KeyEncryptionKeyName = "kek" });
        services.AddSecurityEvents();
        services.AddSharedSignalsTransmitter(new SharedSignalsTransmitterOptions
        {
            Issuer = "https://idp.example.com",
            JwksUri = new UriBuilder(Uri.UriSchemeHttps, "idp.example.com") { Path = ".well-known/jwks" }.Uri,
            EventsSupported = ["https://schemas.openid.net/secevent/caep/event-type/session-revoked"],
        });
        services.AddMultiTenancy(_ => { }).AddSharedSignals();
        var registered = services
            .Where(descriptor => IsSettingsCheck(descriptor.ServiceType))
            .Select(descriptor => descriptor.ImplementationType)
            .ToHashSet();

        var unregistered = checks
            .Where(check => !registered.Contains(check))
            .Select(check => check.Name)
            .Order(StringComparer.Ordinal)
            .ToArray();
        Assert.True(unregistered.Length == 0, string.Join(", ", unregistered));
    }

    private static bool IsSettingsCheck(Type type)
        => type is { IsGenericType: true } && type.GetGenericTypeDefinition() == typeof(IValidateOptions<>);
}
