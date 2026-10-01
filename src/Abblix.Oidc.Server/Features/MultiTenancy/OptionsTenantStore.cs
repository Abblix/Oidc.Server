// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// The tenants declared in <see cref="MultiTenancyOptions.Tenants"/>, which change only with a restart.
/// </summary>
/// <param name="options">The settings declaring the tenants.</param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class OptionsTenantStore(IOptions<MultiTenancyOptions> options) : ITenantStore
{
    /// <summary>
    /// The version of every tenant the settings declare: they hold one definition for the life of the process.
    /// </summary>
    private const string DeclaredVersion = "";

    /// <inheritdoc />
    public Task<IReadOnlyCollection<StoredTenant>> ListAsync(CancellationToken cancellationToken)
        => Task.FromResult<IReadOnlyCollection<StoredTenant>>(
            [..options.Value.Tenants.Select(tenant => new StoredTenant(tenant, DeclaredVersion))]);
}
