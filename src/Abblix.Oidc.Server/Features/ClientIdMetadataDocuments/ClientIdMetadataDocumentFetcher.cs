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
/// <param name="fetchOptions">The time a fetch may take and the destinations the host named, read on each fetch.
/// </param>
internal sealed partial class ClientIdMetadataDocumentFetcher(
    ILogger<ClientIdMetadataDocumentFetcher> logger,
    IHttpClientFactory httpClientFactory,
    ISecureUriValidator uriValidator,
    IOptionsMonitor<OidcOptions> options,
    IOptionsMonitor<SecureHttpFetchOptions> fetchOptions)
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
        var transport = fetchOptions.CurrentValue;

        // Section 10.7: the server "MUST NOT fetch a Client ID Metadata Document URL ... that resolve[s] to special-use
        // IP addresses". The handler judges the address the name resolves to again before the request is sent
        if (uriValidator.Validate(url) is { } rejection)
            return Refused(url, MetadataDocumentFailure.Terminal($"the URL is not one this server may reach: {rejection}"));

        // A destination the host named reaches past those rules for its own services, chosen by the host or by a
        // registered client; a client identifier is chosen by whoever sends a request, so it is never one of them
        if (SecureUriValidator.IsAllowedDestination(url, transport.AllowedDestinations))
            return Refused(url, MetadataDocumentFailure.Terminal("the URL is one the host allows for its own services"));

        // The client's timeout ends only the wait for the headers, so the whole fetch, body included, has its own
        using var deadline = new CancellationTokenSource(settings.FetchTimeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        try
        {
            using var client = httpClientFactory.CreateClient(ClientIdMetadataDocumentTransport.HttpClientName);
            using var request = new HttpRequestMessage(HttpMethod.Get, url);

            // Section 6: the server "SHOULD send an Accept header of application/json"
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(MediaTypeNames.Application.Json));

            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, linked.Token);
            return await ReadAsync(url, response, settings, linked.Token);
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException)
        {
            // Including a name found to resolve to a private address only now, which may resolve otherwise next time,
            // and a body broken off half way
            return Refused(url, MetadataDocumentFailure.Transient($"the request failed: {exception.Message}"));
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Refused(url, MetadataDocumentFailure.Transient("the request timed out"));
        }
    }

    private async Task<Result<FetchedDocument, MetadataDocumentFailure>> ReadAsync(
        Uri url,
        HttpResponseMessage response,
        ClientIdMetadataDocumentOptions settings,
        CancellationToken cancellationToken)
    {
        // Section 6: "The authorization server MUST treat all other HTTP status codes as an error response". Section
        // 6.1 calls a failure transient when it is "comparable in spirit to the temporarily_unavailable condition",
        // which a server error, a timeout and a refusal to serve so many requests are; any other status is the
        // document's own answer
        if (response.StatusCode != HttpStatusCode.OK)
        {
            var reason = $"the response status is {(int)response.StatusCode}";
            return Refused(url, MayPass(response.StatusCode)
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

        var content = await BoundedContent.ReadAsync(response.Content, settings.MaxDocumentSize, cancellationToken);
        if (content is null)
        {
            return Refused(url, MetadataDocumentFailure.Terminal(
                $"the document is longer than {settings.MaxDocumentSize} bytes"));
        }

        JsonNode? document;
        try
        {
            // A member repeated is refused here rather than met by the first reading of it, which would throw
            document = JsonNode.Parse(content, documentOptions: new JsonDocumentOptions { AllowDuplicateProperties = false });
        }
        catch (JsonException exception)
        {
            return Refused(url, MetadataDocumentFailure.Terminal($"the document is not valid JSON: {exception.Message}"));
        }

        if (document is not JsonObject json)
            return Refused(url, MetadataDocumentFailure.Terminal("the document is not a JSON object"));

        return new FetchedDocument(json, DocumentLifetime.Of(response, settings));
    }

    private static bool MayPass(HttpStatusCode status)
        => status is HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests ||
           (int)status >= (int)HttpStatusCode.InternalServerError;


    private MetadataDocumentFailure Refused(Uri url, MetadataDocumentFailure failure)
    {
        LogFetchFailed(url, failure.MayPass, failure.Reason);
        return failure;
    }
}
