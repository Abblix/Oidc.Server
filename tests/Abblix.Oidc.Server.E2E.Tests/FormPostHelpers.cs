// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;

namespace Abblix.Oidc.Server.E2E.Tests;

internal static class FormPostHelpers
{
    /// <summary>
    /// Posts <paramref name="form"/> as <c>application/x-www-form-urlencoded</c> to
    /// <paramref name="endpoint"/>, optionally attaching a DPoP proof header. Returns
    /// the raw response so callers can inspect status, body, and headers. Used by every
    /// E2E helper that hits /par, /token, /refresh, or other form-based OAuth endpoints
    /// - keeps the HttpRequestMessage + FormUrlEncodedContent + WithDPoPHeader plumbing
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