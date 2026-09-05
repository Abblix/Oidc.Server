// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;

/// <summary>
/// Per-request DPoP header attachment for E2E scenarios. The proof is request-bound
/// (htm + htu carve out the exact endpoint), so DPoP is NOT a default-header
/// candidate the way Authorization is - every request needs its own proof minted
/// against its own method + URI. These helpers wrap that wiring so test code reads
/// at flow-step granularity.
/// </summary>
internal static class HttpClientDPoPExtensions
{
    /// <summary>
    /// Attaches the supplied proof JWT to <paramref name="request"/> in the RFC 9449
    /// <c>DPoP</c> header. The caller is responsible for having minted the proof against
    /// the same method + URI the request will hit - there is no AS leniency on either.
    /// </summary>
    public static HttpRequestMessage WithDPoPHeader(this HttpRequestMessage request, string proofJwt)
    {
        request.Headers.Add(HttpRequestHeaders.DPoP, proofJwt);
        return request;
    }
}
