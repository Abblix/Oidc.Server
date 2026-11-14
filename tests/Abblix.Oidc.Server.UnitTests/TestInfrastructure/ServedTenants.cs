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
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Abblix.Oidc.Server.UnitTests.TestInfrastructure;

/// <summary>
/// The server's own catalog over a store whose tenants a test lists, released as the catalog releases them: one
/// refresh after a tenant leaves the list keeps it, as a request may still be serving it, and the refresh after the
/// next period lets it go.
/// </summary>
internal sealed class ServedTenants
{
    private readonly FakeTimeProvider _time = new();

    public ServedTenants()
    {
        var store = new Mock<ITenantStore>();
        store.Setup(s => s.ListAsync(It.IsAny<CancellationToken>())).ReturnsAsync(() => Listed.ToArray());
        var opening = new Mock<ITenantOpening>();
        opening
            .Setup(o => o.OpenAsync(It.IsAny<IReadOnlyCollection<TenantDefinition>>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Dictionary<string, Exception>());
        Catalog = new StoreTenantCatalog(
            NullLogger<StoreTenantCatalog>.Instance,
            store.Object,
            [new TenantDefinitionsCheck()],
            [opening.Object],
            [],
            Options.Create(new OidcOptions()),
            _time);
    }

    /// <summary>The tenants the store lists.</summary>
    public List<StoredTenant> Listed { get; } = [];

    /// <summary>The catalog serving them.</summary>
    public StoreTenantCatalog Catalog { get; }

    /// <summary>Lists <paramref name="tenant"/> and serves it.</summary>
    public async Task<TenantDefinition> ServeAsync(TenantDefinition tenant, CancellationToken cancellationToken)
    {
        Listed.Add(new StoredTenant(tenant, Listed.Count.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        await Catalog.RefreshAsync(cancellationToken);
        return (await Catalog.FindByIdAsync(tenant.Id, cancellationToken))!;
    }

    /// <summary>Reads the store again.</summary>
    public Task RefreshAsync(CancellationToken cancellationToken) => Catalog.RefreshAsync(cancellationToken);

    /// <summary>Reads the store again once the pause a dropped tenant is kept through has passed.</summary>
    public Task RefreshAfterThePauseAsync(CancellationToken cancellationToken)
    {
        _time.Advance(new OidcOptions().RefreshTenantsEvery);
        return Catalog.RefreshAsync(cancellationToken);
    }
}
