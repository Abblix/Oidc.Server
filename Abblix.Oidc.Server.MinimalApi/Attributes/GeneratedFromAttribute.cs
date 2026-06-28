// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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
