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
using System.Text;
using System.Text.Json;
using Abblix.Jwt.ExternalKeys;
using Azure;
using Azure.Core.Pipeline;
using Azure.Storage.Blobs;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Abblix.Jwt.Azure.UnitTests;

/// <summary>
/// Exercises the Blob wire contract of <see cref="BlobKeyRingStore"/> against a stub transport: the
/// conditional create that decides which pod mints a period, the losing side of that race, and the empty-ring and
/// deleted-entry cases a running deployment meets.
/// </summary>
public sealed class BlobKeyRingStoreTests : IDisposable
{
    private readonly List<HttpClient> _httpClients = [];

    private static readonly StoredKey Entry = new()
    {
        Id = "sig-RS256-20260717T000000Z",
        Jwe = "header.wrappedkey.iv.ciphertext.tag",
        CreatedAt = new DateTimeOffset(2026, 7, 17, 0, 0, 0, TimeSpan.Zero),
    };

    private BlobKeyRingStore StoreOver(StubHttpMessageHandler handler)
    {
        var httpClient = new HttpClient(handler);
        _httpClients.Add(httpClient);

        var service = new BlobServiceClient(
            new Uri("https://contoso.blob.core.windows.net"),
            new StaticTokenCredential(),
            new BlobClientOptions { Transport = new HttpClientTransport(httpClient) });

        return new BlobKeyRingStore(
            NullLogger<BlobKeyRingStore>.Instance,
            service.GetBlobContainerClient("oidc-keyring"));
    }

    public void Dispose()
    {
        foreach (var httpClient in _httpClients)
            httpClient.Dispose();
    }

    /// <summary>
    /// Answers the container-create call every operation makes, then defers to the responder.
    /// </summary>
    /// <remarks>
    /// Matched on the verb, not on restype=container alone: a listing carries that same parameter, so matching the
    /// query would answer the list with an empty create response.
    /// </remarks>
    private static StubHttpMessageHandler Blob(Func<HttpRequestMessage, HttpResponseMessage> responder)
        => new(request =>
            request.Method == HttpMethod.Put
            && request.RequestUri!.Query.Contains("restype=container", StringComparison.Ordinal)
                ? new HttpResponseMessage(HttpStatusCode.Created)
                : responder(request));

    [Fact]
    public async Task TryAddAsync_UploadsWithIfNoneMatchAny_SoOnlyTheFirstPodCanWin()
    {
        HttpRequestMessage? seen = null;
        var handler = Blob(request =>
        {
            seen = request;
            return new HttpResponseMessage(HttpStatusCode.Created);
        });

        var won = await StoreOver(handler).TryAddAsync(Entry, TestContext.Current.CancellationToken);

        Assert.True(won);

        // The header IS the coordination: nothing else stops two pods minting one period from both succeeding.
        // Asserting it on the wire is the only proof that ETag.All means what the design assumes.
        Assert.Equal("*", Assert.Single(seen!.Headers.GetValues("If-None-Match")));
        Assert.EndsWith("/oidc-keyring/sig-RS256-20260717T000000Z", seen.RequestUri!.AbsolutePath, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TryAddAsync_ReportsLost_WhenAnotherPodTookThePeriod()
    {
        // Blob answers a conditional create against an existing blob with 409 BlobAlreadyExists. Losing is
        // routine: the winner's key is as good as ours, so the caller drops what it generated.
        var handler = Blob(_ => BlobError(HttpStatusCode.Conflict, "BlobAlreadyExists"));

        var won = await StoreOver(handler).TryAddAsync(Entry, TestContext.Current.CancellationToken);

        Assert.False(won);
    }

    [Fact]
    public async Task TryAddAsync_Throws_WhenA409MeansSomethingElse()
    {
        // A 409 also carries ContainerBeingDeleted and LeaseAlreadyPresent. Reading either as "someone won" would
        // make this pod discard a key nobody stored, and the period would end up with no key at all.
        var handler = Blob(_ => BlobError(HttpStatusCode.Conflict, "ContainerBeingDeleted"));
        var store = StoreOver(handler);

        await Assert.ThrowsAsync<RequestFailedException>(
            () => store.TryAddAsync(Entry, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task TryAddAsync_Throws_WhenTheIdentityCannotWrite()
    {
        // A missing role assignment is our fault and must be loud: swallowed, it would look like an endless race
        // nobody wins, and the ring would stay empty while the provider silently had no key.
        var handler = Blob(_ => BlobError(HttpStatusCode.Forbidden, "AuthorizationPermissionMismatch"));
        var store = StoreOver(handler);

        await Assert.ThrowsAsync<RequestFailedException>(
            () => store.TryAddAsync(Entry, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task LoadAsync_RoundTripsTheEnvelopeAndItsCreationTime()
    {
        var handler = Blob(request => request.RequestUri!.Query.Contains("comp=list", StringComparison.Ordinal)
            ? Xml(BlobList(Entry.Id))
            : Json(JsonSerializer.Serialize(new { Jwe = Entry.Jwe, CreatedAt = Entry.CreatedAt })));

        var entries = await StoreOver(handler).LoadAsync(TestContext.Current.CancellationToken);

        // CreatedAt decides which key signs and when one retires, so a serializer change that dropped or reshaped
        // it would re-age the whole ring rather than fail: pin the round-trip.
        var entry = Assert.Single(entries);
        Assert.Equal(Entry.Id, entry.Id);
        Assert.Equal(Entry.Jwe, entry.Jwe);
        Assert.Equal(Entry.CreatedAt, entry.CreatedAt);
    }

    [Fact]
    public async Task LoadAsync_SkipsAnEntryRetiredBetweenTheListingAndTheRead()
    {
        var handler = Blob(request => request.RequestUri!.Query.Contains("comp=list", StringComparison.Ordinal)
            ? Xml(BlobList(Entry.Id))
            : BlobError(HttpStatusCode.NotFound, "BlobNotFound"));

        var entries = await StoreOver(handler).LoadAsync(TestContext.Current.CancellationToken);

        // Another pod retired it mid-read. That is a race the caller does not care about: the key is gone either
        // way, and failing the whole refresh over it would take the provider down for a routine cleanup.
        Assert.Empty(entries);
    }

    [Fact]
    public async Task RemoveAsync_TreatsAnAbsentEntryAsDone()
    {
        // Two pods may retire the same expired key: removing what is already gone is the outcome both wanted.
        var handler = Blob(_ => BlobError(HttpStatusCode.NotFound, "BlobNotFound"));

        var error = await Record.ExceptionAsync(
            () => StoreOver(handler).RemoveAsync(Entry.Id, TestContext.Current.CancellationToken));

        Assert.Null(error);
    }

    private static HttpResponseMessage BlobError(HttpStatusCode status, string errorCode)
    {
        var response = new HttpResponseMessage(status);
        response.Headers.Add("x-ms-error-code", errorCode);
        return response;
    }

    private static HttpResponseMessage Json(string body)
        => new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private static HttpResponseMessage Xml(string body)
        => new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/xml") };

    private static string BlobList(string name)
        => $"""
            <?xml version="1.0" encoding="utf-8"?>
            <EnumerationResults><Blobs><Blob><Name>{name}</Name><Properties /></Blob></Blobs><NextMarker /></EnumerationResults>
            """;
}
