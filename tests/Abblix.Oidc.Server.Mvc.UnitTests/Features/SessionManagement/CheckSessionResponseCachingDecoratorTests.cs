// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.AspNetCore.SessionManagement;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints.CheckSession.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Mvc.Features.SessionManagement;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Abblix.Oidc.Server.Mvc.UnitTests.Features.SessionManagement;

/// <summary>
/// The check-session page a tenant's request formats is cached for as long as the server serves that tenant.
/// </summary>
public class CheckSessionResponseCachingDecoratorTests
{
    /// <summary>
    /// A page cached for a tenant is formatted again once the server's catalog releases the tenant, so a tenant gone
    /// for good leaves no page in memory and one created again under its id gets a page of its own.
    /// </summary>
    [Fact]
    public async Task APageCachedForATenant_IsFormattedAgainOnceTheTenantIsReleased()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new ListedTenants(
            new StoredTenant(
                new TenantDefinition { Id = "acme", Issuer = new Uri("https://auth.example.com"), Generation = "g1" },
                "1"));
        var clock = new FakeTimeProvider();
        var catalog = new StoreTenantCatalog(
            NullLogger<StoreTenantCatalog>.Instance,
            store,
            [new TenantDefinitionsCheck()],
            [],
            [],
            Options.Create(new OidcOptions()),
            clock);
        await catalog.RefreshAsync(ct);
        var served = new TenantContext { Tenant = (await catalog.FindByIdAsync("acme", ct))! };
        var inner = new CountingFormatter();
        var decorator = new CheckSessionResponseCachingDecorator(
            inner,
            new CheckSessionResponseCache<ActionResult>(Options.Create(new MemoryCacheOptions())),
            new ServedAt(served),
            catalog);
        var response = new CheckSessionResponse("<html/>", "check-session");

        await decorator.FormatResponseAsync(response);
        await decorator.FormatResponseAsync(response);
        Assert.Equal(1, inner.Formatted);

        store.Listed.Clear();
        await catalog.RefreshAsync(ct);
        clock.Advance(new OidcOptions().RefreshTenantsEvery);
        await catalog.RefreshAsync(ct);

        await decorator.FormatResponseAsync(response);
        Assert.Equal(2, inner.Formatted);
    }

    private sealed class ListedTenants(params StoredTenant[] listed) : ITenantStore
    {
        public List<StoredTenant> Listed { get; } = [.. listed];

        public Task<IReadOnlyCollection<StoredTenant>> ListAsync(CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyCollection<StoredTenant>>(Listed.ToArray());
    }

    private sealed class ServedAt(TenantContext served) : ITenantAccessor
    {
        public TenantContext Current => served;
    }

    private sealed class CountingFormatter : ICheckSessionResponseFormatter
    {
        public int Formatted { get; private set; }

        public Task<ActionResult> FormatResponseAsync(CheckSessionResponse response)
        {
            Formatted++;
            return Task.FromResult<ActionResult>(new ContentResult { Content = response.HtmlContent });
        }
    }
}
