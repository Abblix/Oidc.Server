// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Builder;

namespace Abblix.Oidc.Server.Mvc;

/// <summary>
/// Applies a convention to every route <see cref="EndpointRouteBuilderExtensions.MapOidcControllers"/> mapped, and to
/// nothing else of the host's.
/// </summary>
/// <param name="routes">The convention builders of the library's routes.</param>
internal sealed class OidcControllersConventionBuilder(IReadOnlyList<IEndpointConventionBuilder> routes)
    : IEndpointConventionBuilder
{
    /// <inheritdoc />
    public void Add(Action<EndpointBuilder> convention)
    {
        foreach (var route in routes)
            route.Add(convention);
    }

    /// <inheritdoc />
    public void Finally(Action<EndpointBuilder> finallyConvention)
    {
        foreach (var route in routes)
            route.Finally(finallyConvention);
    }
}
