// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Options;

namespace Abblix.Jwt.Vault.UnitTests;

/// <summary>A monitor whose value the test can change, standing in for configuration reload.</summary>
internal sealed class OptionsMonitorStub(VaultTransitOptions options) : IOptionsMonitor<VaultTransitOptions>
{
    public VaultTransitOptions CurrentValue { get; set; } = options;

    public VaultTransitOptions Get(string? name) => CurrentValue;

    public IDisposable? OnChange(Action<VaultTransitOptions, string?> listener) => null;
}
