// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ReplayPrevention;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.AspNetCore.UnitTests.MultiTenancy;

/// <summary>
/// The storage the server registers, which multi-tenancy wraps and so requires to be in place before it.
/// </summary>
internal static class ServerStorageRegistration
{
    /// <summary>
    /// Registers the server's own storage services - the library's registrations, not stand-ins, since they are
    /// what multi-tenancy has to wrap.
    /// </summary>
    public static IServiceCollection AddServerStorage(this IServiceCollection services)
        => services
            .AddLogging()
            .AddDistributedMemoryCache()
            .AddCommonServices()
            .AddReplayPrevention();
}
