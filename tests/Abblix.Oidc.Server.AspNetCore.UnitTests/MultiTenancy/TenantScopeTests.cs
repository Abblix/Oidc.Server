// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Xunit;


namespace Abblix.Oidc.Server.AspNetCore.UnitTests.MultiTenancy;

/// <summary>
/// Work of one tenant run outside any request - an administration job revoking a subject's tokens - through
/// <see cref="TenantScope"/>.
/// </summary>
public sealed class TenantScopeTests : IDisposable
{
    private const string Subject = "alice";

    private static readonly TenantDefinition Acme = new() { Id = "acme", Issuer = new Uri("https://auth.example.com/tenants/acme") };
    private static readonly TenantDefinition Globex = new() { Id = "globex", Issuer = new Uri("https://auth.example.com/tenants/globex") };
    private static readonly TenantDefinition Initech = new() { Id = "initech", Issuer = new Uri("https://auth.example.com/tenants/initech") };

    private readonly ServiceProvider _provider = new ServiceCollection()
        .AddServerStorage()
        .AddTokenRevocation()
        .ServeTenants()
        .BuildServiceProvider();

    public void Dispose() => _provider.Dispose();

    private ITokenRevoker Revoker => _provider.GetRequiredService<ITokenRevoker>();

    private IRevocationCutoffRegistry Cutoffs => _provider.GetRequiredService<IRevocationCutoffRegistry>();

    /// <summary>
    /// A revocation made for a tenant, with no request at all, lands in that tenant's space: the tenant finds it,
    /// another tenant does not.
    /// </summary>
    [Fact]
    public async Task ARevocationOfOneTenantOutsideAnyRequest_KeepsToThatTenant()
    {
        var cancellationToken = TestContext.Current.CancellationToken;

        await Revoker.RevokeSubjectAsync(Acme, Subject, cancellationToken: cancellationToken);

        Assert.NotNull(await Cutoffs.GetCutoffAsync(Acme, RevocationScope.Subject, Subject, cancellationToken));
        Assert.Null(await Cutoffs.GetCutoffAsync(Globex, RevocationScope.Subject, Subject, cancellationToken));
    }

    /// <summary>
    /// Outside any request and any scope there is no tenant to serve, and asking for one is refused.
    /// </summary>
    [Fact]
    public void OutsideAnyRequestAndAnyScope_TheTenantIsRefused()
        => Assert.Throws<InvalidOperationException>(
            () => _provider.GetRequiredService<ITenantAccessor>().CurrentTenant());

    /// <summary>
    /// A scope ends where it is disposed, giving back the tenant that was current before it - including an outer
    /// scope's.
    /// </summary>
    [Fact]
    public void AScope_GivesBackTheTenantCurrentBeforeIt()
    {
        var accessor = _provider.GetRequiredService<ITenantAccessor>();

        using (TenantScope.Enter(Acme))
        {
            using (TenantScope.Enter(Globex))
                Assert.Equal("globex", accessor.Current?.Tenant.Id);

            Assert.Equal("acme", accessor.Current?.Tenant.Id);
        }

        Assert.Null(accessor.Current);
    }

    /// <summary>
    /// A scope disposed a second time changes nothing: restoring the tenant again would end a later scope's.
    /// </summary>
    [Fact]
    public void ASecondDispose_ChangesNothing()
    {
        using (TenantScope.Enter(Acme))
        {
            var inner = TenantScope.Enter(Globex);
            inner.Dispose();

            using (TenantScope.Enter(Globex))
            {
                inner.Dispose();
                Assert.Equal("globex", TenantScope.Current?.Tenant.Id);
            }

            Assert.Equal("acme", TenantScope.Current?.Tenant.Id);
        }

        Assert.Null(TenantScope.Current);
    }

    /// <summary>
    /// A scope disposed while one entered inside it is still open leaves that one current, and is passed over when
    /// it ends: restoring the ended scope's tenant would run later work as a tenant whose scope is over.
    /// </summary>
    [Fact]
    public void AScopeDisposedBeforeTheOneInsideIt_IsPassedOverWhenThatOneEnds()
    {
        using (TenantScope.Enter(Initech))
        {
            var outer = TenantScope.Enter(Acme);
            var inner = TenantScope.Enter(Globex);

            outer.Dispose();
            Assert.Equal("globex", TenantScope.Current?.Tenant.Id);

            inner.Dispose();
            Assert.Equal("initech", TenantScope.Current?.Tenant.Id);
        }

        Assert.Null(TenantScope.Current);
    }

    /// <summary>
    /// Entered within a request, a scope takes precedence over the tenant the request was resolved to: the work
    /// it wraps was addressed to another tenant on purpose.
    /// </summary>
    [Fact]
    public void WithinARequest_AScopeTakesPrecedence()
    {
        var context = new DefaultHttpContext();
        context.Features.Set(new TenantContext { Tenant = Acme });
        _provider.GetRequiredService<IHttpContextAccessor>().HttpContext = context;
        var accessor = _provider.GetRequiredService<ITenantAccessor>();

        using (TenantScope.Enter(Globex))
            Assert.Equal("globex", accessor.Current?.Tenant.Id);

        Assert.Equal("acme", accessor.Current?.Tenant.Id);
    }

    /// <summary>
    /// The scope flows into the work it wraps across awaits, as the work of an asynchronous consumer does.
    /// </summary>
    [Fact]
    public async Task AScope_FlowsAcrossAwaits()
    {
        var accessor = _provider.GetRequiredService<ITenantAccessor>();

        using (TenantScope.Enter(Acme))
        {
            await Task.Yield();
            Assert.Equal("acme", accessor.Current?.Tenant.Id);
        }
    }
}
