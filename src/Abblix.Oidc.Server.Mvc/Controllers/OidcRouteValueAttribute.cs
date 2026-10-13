// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Mvc.Routing;

namespace Abblix.Oidc.Server.Mvc.Controllers;

/// <summary>
/// Gives a controller of this package a route value that only the routes of
/// <see cref="EndpointRouteBuilderExtensions.MapOidcControllers"/> supply.
/// </summary>
/// <remarks>
/// A conventional route reaches a controller action only when it can produce every route value the action requires,
/// the way an area keeps its controllers away from the routes without <c>{area}</c>. A host's
/// <c>{controller}/{action}</c> route cannot produce this one, so it maps none of the library's actions, and an
/// endpoint the library left unmapped stays unreachable.
/// </remarks>
[AttributeUsage(AttributeTargets.Class)]
internal sealed class OidcRouteValueAttribute() : RouteValueAttribute(Key, Value)
{
    /// <summary>The name of the route value.</summary>
    public const string Key = "abblix-oidc";

    /// <summary>The value the library's routes supply.</summary>
    public const string Value = "server";
}
