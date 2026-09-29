// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.AspNetCore.MultiTenancy;

/// <summary>
/// A service holding data a tenant owns, and the wrapper that keeps that data per tenant.
/// </summary>
/// <remarks>
/// One entry both wraps the service at registration and checks at startup that the server resolves the wrapper,
/// so the list of what is wrapped and the list of what is checked cannot come apart.
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
internal interface ITenantSeam
{
    /// <summary>Wraps the service registered in <paramref name="services"/>.</summary>
    void Wrap(IServiceCollection services);

    /// <summary>
    /// The name of the service when <paramref name="serviceProvider"/> resolves it unwrapped, which is data the
    /// tenants would share; null when it resolves the wrapper or, the service being optional, nothing at all.
    /// </summary>
    string? FindShared(IServiceProvider serviceProvider);
}
