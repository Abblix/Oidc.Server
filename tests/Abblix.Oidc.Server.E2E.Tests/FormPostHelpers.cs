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

using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;

namespace Abblix.Oidc.Server.E2E.Tests;

internal static class FormPostHelpers
{
    /// <summary>
    /// Posts <paramref name="form"/> as <c>application/x-www-form-urlencoded</c> to
    /// <paramref name="endpoint"/>, optionally attaching a DPoP proof header. Returns
    /// the raw response so callers can inspect status, body, and headers. Used by every
    /// E2E helper that hits /par, /token, /refresh, or other form-based OAuth endpoints
    /// — keeps the HttpRequestMessage + FormUrlEncodedContent + WithDPoPHeader plumbing
    /// in one place.
    /// </summary>
    public static async Task<HttpResponseMessage> PostFormAsync(
        HttpClient client,
        Uri endpoint,
        IEnumerable<KeyValuePair<string, string>> form,
        string? dpopProof = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = new FormUrlEncodedContent(form),
        };
        if (dpopProof is not null)
            request.WithDPoPHeader(dpopProof);
        return await client.SendAsync(request);
    }
}