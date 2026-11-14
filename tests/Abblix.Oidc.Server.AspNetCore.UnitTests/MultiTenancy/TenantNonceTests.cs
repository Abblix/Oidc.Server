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
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Nonces;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Xunit;


namespace Abblix.Oidc.Server.AspNetCore.UnitTests.MultiTenancy;

/// <summary>
/// Server-issued nonces - the DPoP-Nonce a client echoes back - under multi-tenancy.
/// </summary>
public sealed class TenantNonceTests : IDisposable
{
    private readonly ServiceProvider _provider = new ServiceCollection()
        .AddServerStorage()
        .ServeTenants()
        .BuildServiceProvider();

    public void Dispose() => _provider.Dispose();

    private INonceService Nonces => _provider.GetRequiredService<INonceService>();

    private static TenantDefinition Tenant(string tenantId)
        => new() { Id = tenantId, Issuer = new Uri($"https://auth.example.com/tenants/{tenantId}") };

    /// <summary>
    /// Each tenant signs its nonces with a secret of its own, so one tenant's nonce is not proof of freshness at
    /// another - and still is at the tenant that issued it.
    /// </summary>
    [Fact]
    public async Task ANonceIssuedByOneTenant_FailsAtAnother_AndHoldsAtItsOwn()
    {
        var cancellationToken = TestContext.Current.CancellationToken;

        var nonce = await Nonces.IssueAsync(Tenant("acme"), cancellationToken);

        Assert.Equal(
            NonceValidationFailure.BadSignature,
            await Nonces.ValidateAsync(Tenant("globex"), nonce, cancellationToken));
        Assert.Null(await Nonces.ValidateAsync(Tenant("acme"), nonce, cancellationToken));
    }
}
