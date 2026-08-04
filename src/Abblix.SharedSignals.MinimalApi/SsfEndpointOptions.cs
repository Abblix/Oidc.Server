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

using Abblix.Jwt;
using Microsoft.AspNetCore.Http;

namespace Abblix.SharedSignals.MinimalApi;

/// <summary>
/// What the endpoint adapter leaves to the host: how an authenticated request maps to the
/// receiver identity every management operation is scoped by. Authentication itself stays with
/// the host's middleware - SSF 1.0 Section 7.1.1 deliberately leaves the scheme open.
/// </summary>
public sealed record SsfEndpointOptions
{
    /// <summary>
    /// Extracts the receiver identity from the authenticated request; null answers the request
    /// with 401. The default reads the "sub" claim and falls back to the identity name - the
    /// two places the common authentication handlers put a caller's identifier.
    /// </summary>
    public Func<HttpContext, string?> ReceiverIdSelector { get; init; } = DefaultReceiverId;

    private static string? DefaultReceiverId(HttpContext context)
        => context.User.FindFirst(IanaClaimTypes.Sub)?.Value
           ?? context.User.Identity?.Name;
}
