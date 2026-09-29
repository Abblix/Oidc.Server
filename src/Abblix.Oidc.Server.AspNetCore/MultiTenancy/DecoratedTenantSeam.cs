// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.AspNetCore.MultiTenancy;

/// <summary>
/// A service one instance of which serves every tenant, the wrapper keeping each tenant's data apart by key.
/// </summary>
/// <inheritdoc cref="TenantSeam{TService, TWrapper}"/>
[Experimental(MultiTenancyDiagnostics.Experimental)]
internal sealed class DecoratedTenantSeam<TService, TWrapper>(object? key = null, bool required = true)
    : TenantSeam<TService, TWrapper>(key, required)
    where TService : class
    where TWrapper : class, TService
{
    /// <inheritdoc />
    protected override void WrapRegistration(IServiceCollection services, int index)
        => services.DecorateKeyed<TService, TWrapper>(Key);
}
