// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Abblix.Oidc.Server.E2E.Tests;

/// <summary>
/// A host factory that test classes running in parallel share, as both end-to-end suites share theirs.
/// </summary>
/// <typeparam name="TEntryPoint">The entry point of the host it boots.</typeparam>
public abstract class SharedHostFactory<TEntryPoint> : WebApplicationFactory<TEntryPoint>
    where TEntryPoint : class
{
    /// <summary>
    /// Serializes the calls that make WebApplicationFactory record what it handed out. It keeps each client and
    /// each host variant in a list without a lock, and the test classes sharing this host run in parallel: two
    /// callers growing a list at once leave an empty slot in it, and disposing the factory at the end of the run
    /// then throws on that slot.
    /// </summary>
    private readonly Lock _handouts = new();

    /// <summary>
    /// A client of this host, created one caller at a time (see <see cref="_handouts"/>).
    /// </summary>
    public new HttpClient CreateClient(WebApplicationFactoryClientOptions options)
    {
        lock (_handouts)
            return base.CreateClient(options);
    }

    /// <summary>
    /// A variant of this host, created one caller at a time (see <see cref="_handouts"/>).
    /// </summary>
    public new WebApplicationFactory<TEntryPoint> WithWebHostBuilder(Action<IWebHostBuilder> configuration)
    {
        lock (_handouts)
            return base.WithWebHostBuilder(configuration);
    }
}
