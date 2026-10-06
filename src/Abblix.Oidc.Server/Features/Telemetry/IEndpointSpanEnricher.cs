// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics;

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <summary>
/// Adds attributes of the host's own to the span of each endpoint request, beside the server's.
/// </summary>
/// <remarks>
/// Called once per request, after the server has tagged the span and before the request is handled, and only when
/// the span is recorded, so a host that receives no traces pays nothing for it. The attributes it adds are the
/// host's: the server's table in <see cref="TelemetryTags"/> does not list them, and what they may carry about a
/// client or an end user is the host's decision. Every enricher registered runs, as a singleton.
/// <code>
/// public sealed class ScopeCountEnricher : IEndpointSpanEnricher
/// {
///     public void Enrich(Activity span, string endpoint, object? request)
///     {
///         if (request is TokenRequest tokenRequest)
///             span.SetTag("app.token.scope_count", tokenRequest.Scope.Length);
///     }
/// }
/// </code>
/// It is registered beside the server: <c>services.AddSingleton&lt;IEndpointSpanEnricher, ScopeCountEnricher&gt;()</c>.
/// </remarks>
public interface IEndpointSpanEnricher
{
    /// <summary>
    /// Adds the host's attributes to <paramref name="span"/>.
    /// </summary>
    /// <param name="span">The span of the endpoint request.</param>
    /// <param name="endpoint">The endpoint, one of <see cref="TelemetryEndpoints"/>.</param>
    /// <param name="request">The request the endpoint handles, as its handler receives it first, or null for an
    /// endpoint whose handler takes none.</param>
    void Enrich(Activity span, string endpoint, object? request);
}
