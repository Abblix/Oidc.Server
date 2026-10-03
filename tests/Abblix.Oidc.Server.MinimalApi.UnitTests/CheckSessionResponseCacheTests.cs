// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.MinimalApi.Features.SessionManagement;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.MinimalApi.UnitTests;

public class CheckSessionResponseCacheTests
{
    /// <summary>
    /// A check-session page is kept until the issuer it was formatted for is released, so a server whose tenants
    /// come and go does not keep the page of every tenant it ever served.
    /// </summary>
    [Fact]
    public async Task APage_IsKeptUntilItsIssuerIsReleased()
    {
        var cache = new CheckSessionResponseCache(Options.Create(new MemoryCacheOptions()));
        using var released = new CancellationTokenSource();
        var formatted = 0;
        Task<IResult> Format()
        {
            formatted++;
            return Task.FromResult(Results.Ok());
        }

        await cache.GetOrAddAsync("acme", Format, released.Token);
        await cache.GetOrAddAsync("acme", Format, released.Token);
        Assert.Equal(1, formatted);

        await released.CancelAsync();
        await cache.GetOrAddAsync("acme", Format, CancellationToken.None);
        Assert.Equal(2, formatted);
    }
}
