// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore.SessionManagement;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.AspNetCore.UnitTests.SessionManagement;

public class CheckSessionResponseCacheTests
{
    [Fact]
    public async Task APage_IsKeptUntilItsIssuerIsReleased()
    {
        var cache = new CheckSessionResponseCache<object>(Options.Create(new MemoryCacheOptions()));
        using var released = new CancellationTokenSource();
        var formatted = 0;
        Task<object> Format()
        {
            formatted++;
            return Task.FromResult(new object());
        }

        await cache.GetOrAddAsync("acme", Format, released.Token);
        await cache.GetOrAddAsync("acme", Format, released.Token);
        Assert.Equal(1, formatted);

        await released.CancelAsync();
        await cache.GetOrAddAsync("acme", Format, CancellationToken.None);
        Assert.Equal(2, formatted);
    }
}
