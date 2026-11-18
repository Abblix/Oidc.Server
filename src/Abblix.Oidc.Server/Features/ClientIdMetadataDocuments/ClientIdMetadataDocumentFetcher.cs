// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Http.Headers;
using System.Net.Mime;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;

/// <summary>
/// Fetches a client's metadata document from its client identifier URL, on the SSRF-guarded transport, and says how
/// long the response may be held.
/// </summary>
/// <remarks>
/// <see cref="ISecureHttpFetcher"/> is not used because it cannot carry what the draft asks of this fetch: it accepts
/// any successful status but 204 where section 6 has the document "served with a 200 OK HTTP status code" and every
/// other status treated as an error, bounds the size only by a declared Content-Length, and says nothing of the
/// response's cache headers, which section 6.2 has the server respect. The transport is the same one: its primary
/// handler is the SSRF validation, and it follows no redirect, which section 6 forbids ("MUST NOT automatically follow
/// HTTP redirects").
/// </remarks>
/// <param name="logger">Records why a fetch failed.</param>
/// <param name="httpClientFactory">Creates the client registered as
/// <see cref="ClientIdMetadataDocumentTransport.HttpClientName"/>.</param>
/// <param name="uriValidator">The synchronous SSRF rules, applied before the request so a URL refused on them is a
/// refusal on trust grounds rather than a network failure.</param>
/// <param name="options">The size limit and the cache bounds, read on each fetch.</param>
internal sealed partial class ClientIdMetadataDocumentFetcher(
    ILogger<ClientIdMetadataDocumentFetcher> logger,
    IHttpClientFactory httpClientFactory,
    ISecureUriValidator uriValidator,
    IOptionsMonitor<OidcOptions> options)
{
    private const string JsonSuffix = "+json";

    /// <summary>
    /// Fetches the document at <paramref name="url"/>.
    /// </summary>
    /// <param name="url">The client identifier URL.</param>
    /// <param name="cancellationToken">Stops the fetch.</param>
    /// <returns>The document and how long it may be held, or why it could not be had and whether that may pass.
    /// </returns>
    public async Task<Result<FetchedDocument, MetadataDocumentFailure>> FetchAsync(
        Uri url,
        CancellationToken cancellationToken = default)
    {
        var settings = options.CurrentValue.ClientIdMetadataDocuments;

        // Section 10.7: the server "MUST NOT fetch a Client ID Metadata Document URL ... that resolve[s] to special-use
        // IP addresses". The handler checks again, after resolving the name, right before the connection
        if (uriValidator.Validate(url) is { } rejection)
            return Refused(url, MetadataDocumentFailure.Terminal($"the URL is not one this server may reach: {rejection}"));

        using var client = httpClientFactory.CreateClient(ClientIdMetadataDocumentTransport.HttpClientName);
        using var request = new HttpRequestMessage(HttpMethod.Get, url);

        // Section 6: the server "SHOULD send an Accept header of application/json"
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(MediaTypeNames.Application.Json));

        HttpResponseMessage response;
        try
        {
            response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        }
        catch (HttpRequestException exception)
        {
            // Including a name found to resolve to a private address only now, which may resolve otherwise next time
            return Refused(url, MetadataDocumentFailure.Transient($"the request failed: {exception.Message}"));
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Refused(url, MetadataDocumentFailure.Transient("the request timed out"));
        }

        using (response)
            return await ReadAsync(url, response, settings, cancellationToken);
    }

    private async Task<Result<FetchedDocument, MetadataDocumentFailure>> ReadAsync(
        Uri url,
        HttpResponseMessage response,
        ClientIdMetadataDocumentOptions settings,
        CancellationToken cancellationToken)
    {
        // Section 6: "The authorization server MUST treat all other HTTP status codes as an error response". Section
        // 6.1 calls a failure transient when it is "comparable in spirit to the temporarily_unavailable condition",
        // which a server error is; any other status is the document's own answer
        if (response.StatusCode != HttpStatusCode.OK)
        {
            var reason = $"the response status is {(int)response.StatusCode}";
            return Refused(url, (int)response.StatusCode >= (int)HttpStatusCode.InternalServerError
                ? MetadataDocumentFailure.Transient(reason)
                : MetadataDocumentFailure.Terminal(reason));
        }

        // Section 4: the document "MAY also be served with more specific content types as long as the response is
        // JSON and conforms to application/<AS-defined>+json"
        var mediaType = response.Content.Headers.ContentType?.MediaType;
        if (mediaType is null ||
            !(mediaType.Equals(MediaTypeNames.Application.Json, StringComparison.OrdinalIgnoreCase) ||
              mediaType.EndsWith(JsonSuffix, StringComparison.OrdinalIgnoreCase)))
        {
            return Refused(url, MetadataDocumentFailure.Terminal($"the response is not JSON but {mediaType ?? "untyped"}"));
        }

        var content = await ReadBoundedAsync(response.Content, settings.MaxDocumentSize, cancellationToken);
        if (content is null)
        {
            return Refused(url, MetadataDocumentFailure.Terminal(
                $"the document is longer than {settings.MaxDocumentSize} bytes"));
        }

        JsonNode? document;
        try
        {
            document = JsonNode.Parse(content);
        }
        catch (JsonException exception)
        {
            return Refused(url, MetadataDocumentFailure.Terminal($"the document is not valid JSON: {exception.Message}"));
        }

        if (document is not JsonObject json)
            return Refused(url, MetadataDocumentFailure.Terminal("the document is not a JSON object"));

        return new FetchedDocument(json, LifetimeOf(response, settings));
    }

    /// <summary>
    /// The response body, or null when it holds more than <paramref name="limit"/> bytes.
    /// </summary>
    /// <remarks>
    /// Section 10.11 has the server stop "after a maximum number of bytes and treating the response as an error if
    /// that limit is reached before the document has been fully read", so the body is read up to one byte past the
    /// limit whatever its Content-Length says, and a declared length past it is refused without reading.
    /// </remarks>
    private static async Task<byte[]?> ReadBoundedAsync(HttpContent content, int limit, CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength > limit)
            return null;

        await using var stream = await content.ReadAsStreamAsync(cancellationToken);
        var buffer = new byte[limit + 1];
        var length = 0;
        int read;
        while (length < buffer.Length &&
               (read = await stream.ReadAsync(buffer.AsMemory(length), cancellationToken)) > 0)
        {
            length += read;
        }

        return length > limit ? null : buffer[..length];
    }

    /// <summary>
    /// How long the response may be held: what its Cache-Control says, never longer than the host's maximum, and the
    /// host's minimum when it says nothing.
    /// </summary>
    /// <remarks>
    /// Section 6.2: the server "SHOULD respect HTTP cache headers [RFC9111]", the Expires header "need not be honored,
    /// since Cache-Control takes precedence", and it "SHOULD enforce a maximum effective cache duration regardless of
    /// the cache directives in the response" and "a minimum effective cache duration when none is otherwise
    /// indicated". The server is the only reader of what it holds, so the directives of a shared cache (s-maxage) are
    /// not its own.
    /// </remarks>
    internal static TimeSpan LifetimeOf(HttpResponseMessage response, ClientIdMetadataDocumentOptions settings)
    {
        var cacheControl = response.Headers.CacheControl;
        if (cacheControl is { NoStore: true } or { NoCache: true })
            return TimeSpan.Zero;

        if (cacheControl?.MaxAge is not { } maxAge)
            return Shortest(settings.MinimumCacheDuration, settings.MaximumCacheDuration);

        // The Age header says how much of that lifetime has already passed in a cache on the way
        var remaining = maxAge - (response.Headers.Age ?? TimeSpan.Zero);
        return remaining <= TimeSpan.Zero ? TimeSpan.Zero : Shortest(remaining, settings.MaximumCacheDuration);
    }

    private static TimeSpan Shortest(TimeSpan first, TimeSpan second) => first < second ? first : second;

    private MetadataDocumentFailure Refused(Uri url, MetadataDocumentFailure failure)
    {
        LogFetchFailed(url, failure.MayPass, failure.Reason);
        return failure;
    }
}
