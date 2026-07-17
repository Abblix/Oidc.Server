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

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace Abblix.Oidc.Server.Vault;

/// <summary>
/// Talks to Vault / OpenBao over the <see cref="HttpClient"/> configured by <c>AddVaultCustodian</c>, whose base
/// address stops at the server's <c>/v1/</c> root and whose handler chain carries the auth token.
/// </summary>
internal sealed class ApiClient(HttpClient httpClient) : IApiClient
{
    /// <summary>
    /// Names the configured client. The transport is shared between the engines, so it is registered under a name
    /// of its own rather than as the typed client of whichever consumer came first.
    /// </summary>
    internal const string ClientName = "Abblix.Oidc.Server.Vault";

    /// <inheritdoc />
    public async Task<Response> SendAsync(
        HttpMethod method,
        string path,
        object? body,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, path);
        if (body is not null)
            request.Content = JsonContent.Create(body);

        using var response = await httpClient.SendAsync(request, cancellationToken);
        var payload = await response.Content.ReadAsStringAsync(cancellationToken);
        return new Response(
            response.StatusCode,
            string.IsNullOrEmpty(payload) ? null : JsonDocument.Parse(payload));
    }
}
