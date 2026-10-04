// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// What turning multi-tenancy on returns, so a feature that has to be made per tenant is turned on after it, by a
/// call on this builder rather than on the service collection.
/// </summary>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public interface IMultiTenancyBuilder
{
    /// <summary>
    /// The services multi-tenancy was turned on in.
    /// </summary>
    IServiceCollection Services { get; }
}
