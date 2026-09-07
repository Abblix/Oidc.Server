// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text;
using System.Text.Json;
using Abblix.Jwt.ExternalKeys;
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


    [Fact]
    public async Task AStorageAccountThatCannotBeReachedIsTemporary()
    {
        // The ring rides the same reading as the keys themselves: a connection that could not be made says
        // nothing about the request. Left as the SDK's own exception it reaches a caller that cannot read it,
        // and the Vault side of this ring already answers the same way.
        var handler = new StubHttpMessageHandler(_ => throw new HttpRequestException("no route to host"));

        await Assert.ThrowsAsync<KeyCustodianUnavailableException>(
            () => StoreOver(handler).LoadAsync(TestContext.Current.CancellationToken));
    }


    [Fact]
    public async Task AStorageAccountThatCannotBeReachedIsTemporaryWhenMinting()
    {
        // The mint path carries its own classification, and only its own row can say so: the read path being
        // classified proves nothing about this one, which is what made the claim about this change too wide.
        // The container create is allowed to succeed, so the failure happens on the upload - the call this row
        // is named for, rather than the one the read path already covers.
        var handler = Blob(_ => throw new HttpRequestException("no route to host"));

        await Assert.ThrowsAsync<KeyCustodianUnavailableException>(
            () => StoreOver(handler).TryAddAsync(Entry, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task AStorageAccountThatCannotBeReachedIsTemporaryWhenRemoving()
    {
        // And the removal path too. Its only other row asserts that an absent entry raises nothing, so without
        // this one the classification could be dropped there and the suite would stay green.
        var handler = new StubHttpMessageHandler(_ => throw new HttpRequestException("no route to host"));

        await Assert.ThrowsAsync<KeyCustodianUnavailableException>(
            () => StoreOver(handler).RemoveAsync("any", TestContext.Current.CancellationToken));
    }

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
        // The filter reads the error code, not the status: a 409 that is not the race must not be read as
        // "someone won", or this pod discards a key nobody stored and the period ends up with no key at all.
        // The code below is chosen for being neither the race nor the transient one - the ring takes no leases,
        // so it is an illustration of a third 409 rather than one this path produces.
        var handler = Blob(_ => BlobError(HttpStatusCode.Conflict, "LeaseAlreadyPresent"));
        var store = StoreOver(handler);

        await Assert.ThrowsAsync<KeyCustodianFailedException>(
            () => store.TryAddAsync(Entry, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task AContainerBeingDeletedIsTemporary()
    {
        // The one failure the status cannot place: 409 is both the mint race and a container whose delete has
        // not finished, and only the second clears on its own. Read from the status alone it joins the refusals
        // that never clear, and the caller is told never to come back from a condition that does end.
        //
        // This row answers the upload. The classification behind it is one and the same for every call, so
        // the row below is not a second path being covered - it differs only in which SDK call raises and
        // under which operation name the failure is reported.
        var handler = Blob(_ => BlobError(HttpStatusCode.Conflict, "ContainerBeingDeleted"));

        await Assert.ThrowsAsync<KeyCustodianUnavailableException>(
            () => StoreOver(handler).TryAddAsync(Entry, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task AContainerBeingDeletedIsTemporaryWhenTheContainerIsCreated()
    {
        // The create is where a container mid-delete is actually met, and it is the call that cannot proceed
        // until the delete finishes. Reading and minting both open with it; removal does not, so removal
        // meets a half-deleted container only on the delete itself.
        var handler = new StubHttpMessageHandler(request => request.Method == HttpMethod.Put
            ? BlobError(HttpStatusCode.Conflict, "ContainerBeingDeleted")
            : Xml(BlobList(Entry.Id)));

        await Assert.ThrowsAsync<KeyCustodianUnavailableException>(
            () => StoreOver(handler).LoadAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task LoadAsync_Fails_WhenTheContainerIsGone()
    {
        // A container removed under a running deployment answers 404 on every entry. Read by status alone
        // each entry looks retired, the ring comes back empty, and empty is the bootstrap signal that starts
        // minting - so a wrong read here does not fail, it silently issues a key.
        var handler = Blob(request => request.RequestUri!.Query.Contains("comp=list", StringComparison.Ordinal)
            ? Xml(BlobList(Entry.Id))
            : BlobError(HttpStatusCode.NotFound, "ContainerNotFound"));

        await Assert.ThrowsAsync<KeyCustodianFailedException>(
            () => StoreOver(handler).LoadAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task TryAddAsync_Throws_WhenTheIdentityCannotWrite()
    {
        // A missing role assignment is our fault and must be loud: swallowed, it would look like an endless race
        // nobody wins, and the ring would stay empty while the provider silently had no key.
        var handler = Blob(_ => BlobError(HttpStatusCode.Forbidden, "AuthorizationPermissionMismatch"));
        var store = StoreOver(handler);

        await Assert.ThrowsAsync<KeyCustodianFailedException>(
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

    [Fact]
    public async Task RemoveAsync_Fails_WhenTheContainerIsGone()
    {
        // A container that is gone answers 404 as well, and the SDK's delete-if-exists cannot tell the two
        // apart. Reporting that as done says the key was retired when nothing was asked of anything, and the
        // operator learns of the missing container only on the next load.
        var handler = Blob(_ => BlobError(HttpStatusCode.NotFound, "ContainerNotFound"));

        await Assert.ThrowsAsync<KeyCustodianFailedException>(
            () => StoreOver(handler).RemoveAsync(Entry.Id, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task LoadAsync_Fails_WhenA404CarriesNoErrorCode()
    {
        // A proxy in front of the account can answer 404 without the header the code is read from. The ring
        // then cannot tell a retired entry from a missing container, and it fails rather than reporting a
        // shorter ring: a ring short of an entry is indistinguishable from one that has been trimmed, and
        // the empty end of that scale starts a mint. This row exists to make that choice deliberate.
        var handler = Blob(request => request.RequestUri!.Query.Contains("comp=list", StringComparison.Ordinal)
            ? Xml(BlobList(Entry.Id))
            : new HttpResponseMessage(HttpStatusCode.NotFound));

        await Assert.ThrowsAsync<KeyCustodianFailedException>(
            () => StoreOver(handler).LoadAsync(TestContext.Current.CancellationToken));
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
