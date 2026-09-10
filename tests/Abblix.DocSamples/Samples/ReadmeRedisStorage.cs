// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

// <ambient>
using Microsoft.Extensions.DependencyInjection;
// </ambient>
using Abblix.Oidc.Server.Redis;
using StackExchange.Redis;

namespace Abblix.DocSamples.Samples;

/// <summary>
/// The compiled copy of the registration in the Redis package's README.
/// </summary>
/// <remarks>
/// The two imports below the ambient markers are the ones the README itself shows, and they are shown
/// because the reader has neither: a snippet registering the storage without naming its namespace
/// compiles here, where every library is referenced at once, and fails on the reader's first build.
/// </remarks>
internal static class ReadmeRedisStorageSample
{
    internal static void Configure(IServiceCollection services)
    {
        // <sample>
        services.AddSingleton<IConnectionMultiplexer>(
            ConnectionMultiplexer.Connect("localhost:6379"));

        services.AddRedisEntityStorage();
        // </sample>
    }
}
