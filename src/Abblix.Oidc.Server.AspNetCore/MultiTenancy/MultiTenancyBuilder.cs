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
/// The builder <see cref="MultiTenancyExtensions.AddMultiTenancy"/> returns.
/// </summary>
/// <param name="services">The services multi-tenancy was turned on in.</param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
internal sealed class MultiTenancyBuilder(IServiceCollection services) : IMultiTenancyBuilder
{
    /// <inheritdoc />
    public IServiceCollection Services => services;
}
