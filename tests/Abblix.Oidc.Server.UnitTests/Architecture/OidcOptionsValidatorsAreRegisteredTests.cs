// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Linq;
using Abblix.Oidc.Server;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Architecture;

/// <summary>
/// Every check of the server's settings is registered by the server's own wiring, so a check written but never
/// registered - which every test calling it directly still passes - fails here instead of letting a deployment start
/// with settings it was written to refuse.
/// </summary>
/// <remarks>
/// The checks are found in the compiled server, so a check added later is held here without anybody extending a list.
/// The wiring is the full server with each feature a host turns on by a call of its own.
/// </remarks>
public class OidcOptionsValidatorsAreRegisteredTests
{
    /// <summary>
    /// Checks a host gets from another package's wiring, each with the call that brings it.
    /// </summary>
    private static readonly HashSet<Type> RegisteredElsewhere =
    [
        // Multi-tenancy is turned on through the ASP.NET Core package, which registers the tenants' own check.
#pragma warning disable ABXMT001 // The feature is experimental for its consumers; this test is where its wiring is checked.
        typeof(TenantOwnedOptionsValidator),
#pragma warning restore ABXMT001
    ];

    [Fact]
    public void EveryCheckOfTheServerSettings_IsRegisteredByTheServer()
    {
        var checks = typeof(OidcOptions).Assembly.GetTypes()
            .Where(type => type is { IsAbstract: false, IsInterface: false }
                           && typeof(IValidateOptions<OidcOptions>).IsAssignableFrom(type))
            .ToHashSet();
        Assert.Contains(typeof(ClockSkewCeilingValidator), checks);

        var services = new ServiceCollection();
        services.AddBackChannelAuthentication();
        services.AddDeviceAuthorization();
        services.AddOidcCore((_, _) => { });
        var registered = services
            .Where(descriptor => descriptor.ServiceType == typeof(IValidateOptions<OidcOptions>))
            .Select(descriptor => descriptor.ImplementationType)
            .ToHashSet();

        var unregistered = checks
            .Where(check => !registered.Contains(check) && !RegisteredElsewhere.Contains(check))
            .Select(check => check.Name)
            .Order(StringComparer.Ordinal)
            .ToArray();
        Assert.True(unregistered.Length == 0, string.Join(", ", unregistered));
    }
}
