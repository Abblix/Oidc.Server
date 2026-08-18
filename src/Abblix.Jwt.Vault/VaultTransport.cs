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

using System.Net.Http.Json;
using System.Text.Json;

namespace Abblix.Jwt.Vault;

/// <summary>
/// The shared HTTP transport to a Vault / OpenBao server.
/// </summary>
/// <remarks>
/// One transport per server, not per engine: the custodian and the key ring talk to the same Vault with the same
/// token, so they resolve one named client from <see cref="IHttpClientFactory"/> and share its connection pool and
/// the one place where the auth header, its redaction and the connection lifetime are settled. The send itself is a
/// function over an <see cref="HttpClient"/>, with no state of its own, so it is an extension rather than a service.
/// <para>
/// The type is public for one member, <see cref="HttpClientName"/>: the transport is what a host configures, and
/// its consumers are internal, so there is nowhere narrower to publish the name from. Everything else stays
/// internal.
/// </para>
/// </remarks>
public static class VaultTransport
{
    /// <summary>
    /// The name the transport's client is registered under, published so a host can configure it without copying
    /// the string: <c>services.AddHttpClient(VaultTransport.HttpClientName)</c> reaches the same client both
    /// engines resolve, and whatever it chains - a resilience pipeline, a proxy, a client certificate - applies to
    /// every Vault call.
    /// </summary>
    /// <remarks>
    /// It is a name of its own rather than a typed client of whichever engine came first, because both engines
    /// share it.
    /// </remarks>
    public const string HttpClientName = "Abblix.Jwt.Vault";

    /// <summary>
    /// Sends a request and hands back what Vault answered, whatever the status. A failure status is not thrown on,
    /// because to some callers it is the answer: a lost cas race, a secret that is not there, a rejected
    /// ciphertext. A caller that wants the opposite says so with <see cref="ApiResponse.EnsureSuccess"/>.
    /// </summary>
    /// <param name="httpClient">The client aimed at the server's <c>/v1/</c> root, carrying the auth token.</param>
    /// <param name="method">The HTTP method, including Vault's own LIST.</param>
    /// <param name="path">The path under the <c>/v1/</c> root, mount included.</param>
    /// <param name="body">The request body, serialized as JSON, or null for a request without one.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>What Vault answered. The caller owns it and disposes it.</returns>
    internal static Task<ApiResponse> SendAsync(
        this HttpClient httpClient,
        HttpMethod method,
        string path,
        object? body,
        CancellationToken cancellationToken)
        => httpClient.SendCoreAsync(method, path, body, anonymous: false, cancellationToken);

    /// <summary>
    /// Sends a request to an unauthenticated Vault path - a login endpoint. No token is attached, and,
    /// decisively, the request does not wait for one: the login request itself is what produces the token
    /// everything else waits for, so sending it through the authenticated path would deadlock on its own result.
    /// </summary>
    /// <param name="httpClient">The client aimed at the server's <c>/v1/</c> root.</param>
    /// <param name="method">The HTTP method.</param>
    /// <param name="path">The path under the <c>/v1/</c> root, mount included.</param>
    /// <param name="body">The request body, serialized as JSON.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>What Vault answered. The caller owns it and disposes it.</returns>
    internal static Task<ApiResponse> SendAnonymousAsync(
        this HttpClient httpClient,
        HttpMethod method,
        string path,
        object? body,
        CancellationToken cancellationToken)
        => httpClient.SendCoreAsync(method, path, body, anonymous: true, cancellationToken);

    private static async Task<ApiResponse> SendCoreAsync(
        this HttpClient httpClient,
        HttpMethod method,
        string path,
        object? body,
        bool anonymous,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, path);
        if (body is not null)
            request.Content = JsonContent.Create(body);
        if (anonymous)
            request.Options.Set(TokenHandler.AnonymousRequest, true);

        using var response = await httpClient.SendAsync(request, cancellationToken);
        var payload = await response.Content.ReadAsStringAsync(cancellationToken);
        return new ApiResponse(response.StatusCode, ParseBody(payload));
    }

    /// <summary>
    /// A body that is not JSON becomes an answer without a body, keeping the status. Vault always
    /// answers JSON, so a non-JSON body means an intermediary spoke instead - a proxy's HTML error
    /// page during an outage is the common shape - and that is a failed call to report, never an
    /// exception to escape into whatever loop made the call.
    /// </summary>
    private static JsonDocument? ParseBody(string payload)
    {
        if (string.IsNullOrEmpty(payload))
            return null;

        try
        {
            return JsonDocument.Parse(payload);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
