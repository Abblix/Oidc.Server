// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.MinimalApi.Attributes;

/// <summary>
/// Marks a partial Minimal API request-model record whose members are produced by the Minimal API model source
/// generator from the given core model type: the bound properties, a static <c>BindAsync(HttpContext)</c> that reads
/// each property from the form/query/headers/connection per the core wire-format markers, the executable validation
/// attributes translated from the core declarative markers, and the implicit operator projecting the bound model onto
/// the core type.
/// </summary>
/// <param name="coreModelType">The core model type in <c>Abblix.Oidc.Server.Model</c> to generate from.</param>
[AttributeUsage(AttributeTargets.Class)]
public sealed class GeneratedFromAttribute(Type coreModelType) : Attribute
{
    /// <summary>The core model type the Minimal API model is generated from.</summary>
    public Type CoreModelType => coreModelType;

    /// <summary>
    /// Indicates that the endpoint also accepts the request via HTTP GET, so the generated <c>BindAsync</c> reads each
    /// value from the query string as well as the posted form (the authorization, userinfo and end-session endpoints).
    /// </summary>
    public bool SupportsGet { get; init; }
}
