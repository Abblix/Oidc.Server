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
/// The host's enrichers of an endpoint's span, together with the request they see.
/// </summary>
/// <param name="Request">The request the handler receives first, or null for a handler that receives none.</param>
/// <param name="Enrichers">The host's enrichers, which add attributes of their own to a recorded span; one that
/// throws fails the request as its handling would, and is recorded so.</param>
internal readonly record struct EndpointEnrichment(object? Request, IEnumerable<IEndpointSpanEnricher>? Enrichers)
{
    /// <summary>
    /// Lets each enricher add its attributes to a span of <paramref name="endpoint"/> that is recorded; a span nobody
    /// records costs them nothing.
    /// </summary>
    public void Apply(Activity? span, string endpoint)
    {
        if (span is not { IsAllDataRequested: true } || Enrichers is null)
            return;

        foreach (var enricher in Enrichers)
            enricher.Enrich(span, endpoint, Request);
    }
}
