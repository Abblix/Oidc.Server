// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SharedSignals.Transmitter;

namespace Abblix.Oidc.Server.SharedSignals;

/// <summary>
/// The streams each tenant declares in configuration, by the tenant's id.
/// </summary>
internal sealed class TenantConfiguredStreams
{
    private readonly Dictionary<string, IReadOnlyList<ConfiguredStream>> _byTenant = new(StringComparer.Ordinal);

    /// <summary>
    /// Takes in the streams <paramref name="tenantId"/> declares.
    /// </summary>
    /// <exception cref="InvalidOperationException">The tenant has declared its streams already.</exception>
    public void Declare(string tenantId, IReadOnlyList<ConfiguredStream> streams)
    {
        if (!_byTenant.TryAdd(tenantId, streams))
        {
            throw new InvalidOperationException(
                $"The streams of tenant '{tenantId}' are declared more than once; declare them in one call.");
        }
    }

    /// <summary>
    /// The streams <paramref name="tenantId"/> declares, or null when it declares none.
    /// </summary>
    public IReadOnlyList<ConfiguredStream>? Of(string tenantId) => _byTenant.GetValueOrDefault(tenantId);
}
