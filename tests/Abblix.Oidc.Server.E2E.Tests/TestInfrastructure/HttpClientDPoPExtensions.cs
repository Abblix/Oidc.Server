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
