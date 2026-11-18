// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.AspNetCore.UnitTests.MultiTenancy;

/// <summary>
/// The step of starting a host in which the server checks itself: the host tells every started service it is about
/// to start before it starts any of them.
/// </summary>
internal static class HostStartup
{
    /// <summary>
    /// Takes the server through that step.
    /// </summary>
    public static async Task StartingAsync(IServiceProvider provider)
    {
        foreach (var service in provider.GetServices<IHostedService>().OfType<IHostedLifecycleService>())
            await service.StartingAsync(TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// What the server refuses to start with, taken through that step.
    /// </summary>
    public static async Task<string> RefusalAsync(IServiceProvider provider)
        => (await Assert.ThrowsAsync<OptionsValidationException>(() => StartingAsync(provider))).Message;
}
