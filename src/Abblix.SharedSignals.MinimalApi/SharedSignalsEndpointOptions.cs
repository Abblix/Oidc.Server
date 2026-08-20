// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Jwt;
using Microsoft.AspNetCore.Http;

namespace Abblix.SharedSignals.MinimalApi;

/// <summary>
/// What the endpoint adapter leaves to the host: how an authenticated request maps to the
/// receiver identity every management operation is scoped by. Authentication itself stays with
/// the host's middleware - SSF 1.0 Section 7.1.1 deliberately leaves the scheme open.
/// </summary>
public sealed record SharedSignalsEndpointOptions
{
    /// <summary>
    /// Extracts the receiver identity from the authenticated request; null answers the request
    /// with 401. The default reads the "sub" claim and falls back to the identity name - the
    /// two places the common authentication handlers put a caller's identifier.
    /// </summary>
    public Func<HttpContext, string?> ReceiverIdSelector { get; init; } = DefaultReceiverId;

    /// <summary>
    /// The route prefix the management surface is mapped under. Behind a rewriting proxy this
    /// is the INTERNAL prefix; what the configuration document advertises is
    /// <see cref="AdvertisedPrefix"/>.
    /// </summary>
    public PathString ManagementPrefix { get; init; } = "/ssf";

    /// <summary>
    /// The management prefix the configuration document advertises, as the outside world
    /// reaches it; unset advertises <see cref="ManagementPrefix"/>. Set it when a proxy in
    /// front rewrites paths, so the document names the external addresses while the routes
    /// stay mapped on the internal ones.
    /// </summary>
    public PathString AdvertisedPrefix { get; init; }

    /// <summary>
    /// Whether <see cref="SharedSignalsEndpointRouteBuilderExtensions.MapSharedSignalsTransmitterEndpoints"/> maps
    /// the configuration document at the canonical well-known address. True by default; false
    /// is for a host whose gateway or CDN answers that address itself. The address is fixed by
    /// SSF 1.0 Section 7.2 and receivers derive it from the issuer, so this flag only
    /// suppresses the route, never moves it - a host that must serve the document on another
    /// internal path pairs it with <see cref="ConfigurationDocumentRoute"/> and
    /// <see cref="SharedSignalsEndpointRouteBuilderExtensions.MapSharedSignalsConfigurationDocument"/>.
    /// </summary>
    public bool MapWellKnownConfiguration { get; init; } = true;

    /// <summary>
    /// The route the configuration document is served on; unset takes the canonical
    /// well-known address derived from the issuer (SSF 1.0 Section 7.2). A set value is
    /// deployment plumbing for a rewriting proxy that maps the canonical address onto an
    /// internal route - the EXTERNAL address never moves, because receivers derive it from
    /// the issuer.
    /// </summary>
    public PathString ConfigurationDocumentRoute { get; init; }

    private static string? DefaultReceiverId(HttpContext context)
        => context.User.FindFirst(IanaClaimTypes.Sub)?.Value
           ?? context.User.Identity?.Name;
}
