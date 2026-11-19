// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientIdMetadataDocuments;

/// <summary>
/// How long a fetched document is held and what is served when fetching it again fails
/// (draft-ietf-oauth-client-id-metadata-document sections 6.1 and 6.2).
/// </summary>
public sealed class HeldMetadataDocumentsTests : IDisposable
{
    private const string Url = "https://client.example.com/metadata.json";
    private const string Document = """{"client_id":"https://client.example.com/metadata.json","client_name":"One"}""";
    private const string Changed = """{"client_id":"https://client.example.com/metadata.json","client_name":"Two"}""";

    private readonly MetadataDocumentServices _services = new();

    public void Dispose() => _services.Dispose();

    private Task<HeldMetadataDocument?> GetAsync() => _services.Get<HeldMetadataDocuments>().GetAsync(Url, new Uri(Url));

    /// <summary>
    /// Section 10.7: the server "MUST NOT fetch a Client ID Metadata Document URL ... that resolve[s] to special-use IP
    /// addresses as defined in [RFC6890]". A document whose host answers with the NAT64 prefix is not fetched, though
    /// it carries a public address, while one answering with a public address is.
    /// </summary>
    [Theory]
    [InlineData("2001:4860:4860::8888", true)]
    [InlineData("64:ff9b::808:808", false)]
    public async Task ADocument_IsFetchedOnlyFromAnAddressNoSpecialPurposeBlockHolds(string resolved, bool fetched)
    {
        MetadataDocumentServices? documents = null;
        using var services = documents = new MetadataDocumentServices(collection => collection
            .AddHttpClient(ClientIdMetadataDocumentTransport.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(provider =>
            {
                // The server's own SSRF validation, with the name answering as the row says
                var guard = new SsrfValidatingHttpMessageHandler(
                    provider.GetRequiredService<IOptions<SecureHttpFetchOptions>>(),
                    provider.GetRequiredService<ISecureUriValidator>(),
                    (_, _) => Task.FromResult(new[] { IPAddress.Parse(resolved) }));
                guard.InnerHandler!.Dispose();
                guard.InnerHandler = documents!.Origin;
                return guard;
            }));
        services.Origin.Serve(Url, Document);

        var held = await services.Get<HeldMetadataDocuments>().GetAsync(Url, new Uri(Url));

        Assert.Equal(fetched, held is not null);
        Assert.Equal(fetched ? 1 : 0, services.Origin.RequestsTo(Url));
    }

    /// <summary>
    /// Section 6.2: the server "MUST NOT cache error responses", so a lookup starting after a fetch failed fetches
    /// again, even one of the same authorization request.
    /// </summary>
    [Fact]
    public async Task ARefusal_IsNotServedToALookupStartingAfterIt()
    {
        _services.Origin.Answer(Url, () => new HttpResponseMessage(HttpStatusCode.NotFound));

        Assert.Null(await GetAsync());
        Assert.Null(await GetAsync());

        Assert.Equal(2, _services.Origin.RequestsTo(Url));
    }

    /// <summary>
    /// Lookups arriving while a fetch runs share it: one request reaches the client's server, and every lookup gets its
    /// outcome.
    /// </summary>
    [Fact]
    public async Task LookupsDuringAFetch_ShareIt()
    {
        var release = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        _services.Origin.AnswerAsync(Url, () => release.Task);

        var first = GetAsync();
        await WaitUntilAsync(() => _services.Origin.RequestsTo(Url) == 1);

        // A lookup joins the running fetch before it returns, so by now the second shares the first's, or has reached
        // the origin with a fetch of its own
        var second = GetAsync();
        release.SetResult(new HttpResponseMessage(HttpStatusCode.NotFound));

        Assert.Null(await first);
        Assert.Null(await second);
        Assert.Equal(1, _services.Origin.RequestsTo(Url));
    }

    /// <summary>
    /// Waits for <paramref name="condition"/>, failing the test should it not come to hold within a bound far past any
    /// load: the bound ends a test gone wrong and never orders one going right.
    /// </summary>
    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var bound = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken, deadline.Token);
        while (!condition())
            await Task.Delay(TimeSpan.FromMilliseconds(5), bound.Token);
    }

    [Fact]
    public async Task ADocument_IsFetchedOnceWhileItsLifetimeLasts_AndAgainAfter()
    {
        _services.Origin.Serve(Url, Document, "max-age=60");

        var first = await GetAsync();
        _services.Clock.Advance(TimeSpan.FromSeconds(59));
        var second = await GetAsync();

        Assert.Same(first, second);
        Assert.Equal(1, _services.Origin.RequestsTo(Url));

        _services.Origin.Serve(Url, Changed, "max-age=60");
        _services.Clock.Advance(TimeSpan.FromSeconds(2));
        var third = await GetAsync();

        Assert.Equal(2, _services.Origin.RequestsTo(Url));
        Assert.Equal("Two", third!.Metadata.ClientName);
    }

    [Fact]
    public async Task ADocumentThatMayNotBeHeld_IsFetchedForEveryRequest()
    {
        _services.Origin.Serve(Url, Document, "no-store");

        Assert.NotNull(await GetAsync());
        Assert.NotNull(await GetAsync());

        Assert.Equal(2, _services.Origin.RequestsTo(Url));
    }

    /// <summary>
    /// A response forbidding its storage leaves nothing to fall back on when the next fetch fails.
    /// </summary>
    [Fact]
    public async Task ADocumentThatMayNotBeHeld_IsNotServedWhenTheNextFetchFails()
    {
        _services.Origin.Serve(Url, Document, "no-store");
        Assert.NotNull(await GetAsync());

        _services.Origin.Unreachable(Url);

        Assert.Null(await GetAsync());
    }

    /// <summary>
    /// Section 6.1: "An authorization server SHOULD NOT discard previously cached valid client metadata on transient
    /// failures", and section 6.2 bounds how long anything is held.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AFetchThatMayPass_IsAnsweredWithTheCopyHeld_UntilTheMaximumHasPassed(bool unreachable)
    {
        _services.Origin.Serve(Url, Document, "max-age=60");
        var held = await GetAsync();

        if (unreachable)
            _services.Origin.Unreachable(Url);
        else
            _services.Origin.Answer(Url, () => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));

        _services.Clock.Advance(TimeSpan.FromMinutes(30));
        Assert.Same(held, await GetAsync());

        _services.Clock.Advance(TimeSpan.FromMinutes(31));
        Assert.Null(await GetAsync());
    }

    /// <summary>
    /// Section 6.2: the server "MUST NOT cache error responses" and "MUST NOT cache documents which are invalid or
    /// malformed", so a document refused on its next fetch is not served from what was held of it.
    /// </summary>
    [Fact]
    public async Task ADocumentRefusedOnItsNextFetch_IsNoLongerServed()
    {
        _services.Origin.Serve(Url, Document, "max-age=60");
        Assert.NotNull(await GetAsync());

        _services.Origin.Serve(Url, """{"client_id":"https://elsewhere.example.com/metadata.json"}""");
        _services.Clock.Advance(TimeSpan.FromMinutes(2));

        Assert.Null(await GetAsync());

        _services.Origin.Serve(Url, Document, "max-age=60");
        Assert.NotNull(await GetAsync());
    }

    [Fact]
    public async Task AFailure_IsNotHeld_SoTheNextRequestFetchesAgain()
    {
        _services.Origin.Answer(Url, () => new HttpResponseMessage(HttpStatusCode.NotFound));
        Assert.Null(await GetAsync());

        _services.Origin.Serve(Url, Document);
        Assert.NotNull(await GetAsync());
        Assert.Equal(2, _services.Origin.RequestsTo(Url));
    }
}
