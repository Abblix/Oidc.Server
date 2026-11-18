// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics;
using Abblix.Oidc.Server.Features.Telemetry;
using Abblix.Oidc.Server.Model;

namespace Abblix.DocSamples.Samples;

// The compiled copy of the sample documenting how a host adds attributes of its own to the span of each endpoint
// request; the sample is a whole class, so it stands here as one.

// <sample>
public sealed class ScopeCountEnricher : IEndpointSpanEnricher
{
    public void Enrich(Activity span, string endpoint, object? request)
    {
        if (request is TokenRequest tokenRequest)
            span.SetTag("app.token.scope_count", tokenRequest.Scope.Length);
    }
}
// </sample>
