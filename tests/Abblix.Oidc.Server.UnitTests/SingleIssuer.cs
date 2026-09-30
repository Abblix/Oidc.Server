// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt.ExternalKeys;
using System;
using System.Collections.Generic;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Abblix.Oidc.Server.Features.ScopeManagement;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.UnitTests;

/// <summary>
/// Services built as a server without tenants builds them: for its one issuer, from <see cref="OidcOptions"/>.
/// </summary>
internal static class SingleIssuer
{
    public static IIssuerSettings Settings => SettingsOf(Options.Create(new OidcOptions()));

    /// <summary>
    /// The settings of the one issuer <paramref name="options"/> configure, read at each use as a reload would be.
    /// </summary>
    public static IIssuerSettings SettingsOf(IOptions<OidcOptions> options, CustodianHeldKeys? custodianKeys = null)
        => new OptionsIssuerSettings(new CurrentOptions(options), custodianKeys: custodianKeys);

    public static ScopeManager ScopeManager(IOptions<OidcOptions> options)
        => new(SettingsOf(options), new SingleIssuerLocal<Dictionary<string, ScopeDefinition>>());

    public static ResourceManager ResourceManager(IOptions<OidcOptions> options)
        => new(SettingsOf(options), new SingleIssuerLocal<Dictionary<Uri, ResourceDefinition>>());

    /// <summary>
    /// Options that never change, served as the monitor the settings read them through.
    /// </summary>
    private sealed class CurrentOptions(IOptions<OidcOptions> options) : IOptionsMonitor<OidcOptions>
    {
        public OidcOptions CurrentValue => options.Value;

        public OidcOptions Get(string? name) => options.Value;

        public IDisposable? OnChange(Action<OidcOptions, string?> listener) => null;
    }
}
