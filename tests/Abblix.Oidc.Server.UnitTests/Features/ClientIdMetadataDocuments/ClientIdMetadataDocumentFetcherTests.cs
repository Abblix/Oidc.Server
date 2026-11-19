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
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Tests.Shared;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientIdMetadataDocuments;

/// <summary>
/// What the fetch of a client's metadata document accepts, refuses and how long it lets the answer be held
/// (draft-ietf-oauth-client-id-metadata-document sections 6, 6.1, 6.2 and 10.11).
/// </summary>
public class ClientIdMetadataDocumentFetcherTests
{
    private const string Url = "https://client.example.com/metadata.json";
    private const string Document = """{"client_id":"https://client.example.com/metadata.json"}""";

    private readonly MetadataDocumentOrigin _origin = new();
    private readonly ClientIdMetadataDocumentOptions _settings = new();
    private readonly SecureHttpFetchOptions _transport = new();

    private ClientIdMetadataDocumentFetcher CreateFetcher()
    {
        var services = new ServiceCollection();
        services.AddHttpClient(ClientIdMetadataDocumentTransport.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => _origin);
        var factory = services.BuildServiceProvider().GetRequiredService<IHttpClientFactory>();

        var oidcOptions = new OidcOptions { ClientIdMetadataDocuments = _settings };
        return new ClientIdMetadataDocumentFetcher(
            NullLogger<ClientIdMetadataDocumentFetcher>.Instance,
            factory,
            new SecureUriValidator(Options.Create(_transport), NullLogger<SecureUriValidator>.Instance),
            Mock.Of<IOptionsMonitor<OidcOptions>>(monitor => monitor.CurrentValue == oidcOptions),
            Mock.Of<IOptionsMonitor<SecureHttpFetchOptions>>(monitor => monitor.CurrentValue == _transport));
    }

    private async Task<FetchedDocument> FetchedAsync()
    {
        var result = await CreateFetcher().FetchAsync(new Uri(Url), TestContext.Current.CancellationToken);
        Assert.True(result.TryGetSuccess(out var document), "the document was expected to be fetched");
        return document;
    }

    private async Task<MetadataDocumentFailure> FailedAsync(string url = Url)
    {
        var result = await CreateFetcher().FetchAsync(new Uri(url), TestContext.Current.CancellationToken);
        Assert.True(result.TryGetFailure(out var failure), "the fetch was expected to fail");
        return failure;
    }

    [Fact]
    public async Task ADocumentServedWith200_IsFetched_AskingForJson()
    {
        _origin.Serve(Url, Document);

        var document = await FetchedAsync();

        Assert.Equal(Url, document.Content["client_id"]!.GetValue<string>());
        var request = Assert.Single(_origin.Requests);
        Assert.Contains(request.Headers.Accept, accept => accept.MediaType == "application/json");
        Assert.False(request.Headers.Contains("Cookie"));
    }

    /// <summary>
    /// Section 6: the document "MUST be served with a 200 OK HTTP status code", and "all other HTTP status codes" are
    /// an error. Section 6.1 counts a server error as a failure that may pass, and anything else as the document's
    /// own answer.
    /// </summary>
    [Theory]
    [InlineData(HttpStatusCode.NonAuthoritativeInformation, false)]
    [InlineData(HttpStatusCode.PartialContent, false)]
    [InlineData(HttpStatusCode.Found, false)]
    [InlineData(HttpStatusCode.NotFound, false)]
    [InlineData(HttpStatusCode.RequestTimeout, true)]
    [InlineData(HttpStatusCode.TooManyRequests, true)]
    [InlineData(HttpStatusCode.InternalServerError, true)]
    [InlineData(HttpStatusCode.ServiceUnavailable, true)]
    public async Task AnyOtherStatus_IsAFailure(HttpStatusCode status, bool mayPass)
    {
        _origin.Answer(Url, () => new HttpResponseMessage(status)
        {
            Content = new StringContent(Document, Encoding.UTF8, "application/json"),
        });

        Assert.Equal(mayPass, (await FailedAsync()).MayPass);
    }

    [Fact]
    public async Task AnUnreachableHost_IsAFailureThatMayPass()
    {
        _origin.Unreachable(Url);
        Assert.True((await FailedAsync()).MayPass);
    }

    /// <summary>
    /// Section 10.7: the server "MUST NOT fetch a Client ID Metadata Document URL ... that resolve[s] to special-use IP
    /// addresses", refused before any request leaves.
    /// </summary>
    [Theory]
    [InlineData("https://127.0.0.1/metadata.json")]
    [InlineData("https://169.254.169.254/metadata.json")]
    [InlineData("https://localhost/metadata.json")]
    public async Task AUrlOfASpecialUseAddress_IsRefusedWithoutARequest(string url)
    {
        _origin.Serve(url, Document);

        Assert.False((await FailedAsync(url)).MayPass);
        Assert.Empty(_origin.Requests);
    }

    [Theory]
    [InlineData("application/json", true)]
    [InlineData("application/client-metadata+json", true)]
    [InlineData("text/plain", false)]
    [InlineData("text/html", false)]
    public async Task OnlyAJsonMediaType_IsRead(string mediaType, bool read)
    {
        _origin.Answer(Url, () => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(Document, Encoding.UTF8, mediaType),
        });

        var result = await CreateFetcher().FetchAsync(new Uri(Url), TestContext.Current.CancellationToken);

        Assert.Equal(read, result.TryGetSuccess(out _));
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("\"https://client.example.com/metadata.json\"")]
    [InlineData("{not json")]
    // A member repeated, at the top and inside a key
    [InlineData("""{"client_id":"https://client.example.com/metadata.json","client_id":"https://client.example.com/metadata.json"}""")]
    [InlineData("""{"client_id":"https://client.example.com/metadata.json","jwks":{"keys":[{"kty":"EC","kty":"EC"}]}}""")]
    public async Task ABodyThatIsNoJsonObject_IsRefused(string body)
    {
        _origin.Serve(Url, body);
        Assert.False((await FailedAsync()).MayPass);
    }

    /// <summary>
    /// Section 10.11: the server stops "after a maximum number of bytes and treating the response as an error if that
    /// limit is reached", whether or not the response declares its length.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ADocumentLongerThanTheLimit_IsRefused(bool declaresLength)
    {
        // A valid document padded with whitespace, so only its length can refuse it: one byte fewer allowed than it has
        var body = Document + new string(' ', 256);
        _settings.MaxDocumentSize = Encoding.UTF8.GetByteCount(body) - 1;
        _origin.Answer(Url, () => new HttpResponseMessage(HttpStatusCode.OK) { Content = Body(body, declaresLength) });

        Assert.False((await FailedAsync()).MayPass);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ADocumentOfExactlyTheLimit_IsRead(bool declaresLength)
    {
        var body = Document + new string(' ', 256);
        _settings.MaxDocumentSize = Encoding.UTF8.GetByteCount(body);
        _origin.Answer(Url, () => new HttpResponseMessage(HttpStatusCode.OK) { Content = Body(body, declaresLength) });

        Assert.NotNull((await FetchedAsync()).Content);
    }

    private static HttpContent Body(string body, bool declaresLength)
        => declaresLength ? new StringContent(body, Encoding.UTF8, "application/json") : new UnsizedContent(body);

    /// <summary>
    /// Section 6.2: the server "SHOULD respect HTTP cache headers", "SHOULD enforce a maximum effective cache duration
    /// regardless of the cache directives in the response" and "a minimum effective cache duration when none is
    /// otherwise indicated".
    /// </summary>
    [Theory]
    [InlineData(null, 300)]
    [InlineData("max-age=120", 120)]
    [InlineData("public, max-age=120", 120)]
    [InlineData("max-age=86400", 3600)]
    [InlineData("max-age=0", 0)]
    [InlineData("no-store", 0)]
    [InlineData("no-cache", 0)]
    [InlineData("no-store, max-age=600", 0)]
    [InlineData("s-maxage=600", 300)]
    public async Task TheLifetime_FollowsCacheControlWithinTheHostsBounds(string? cacheControl, int seconds)
    {
        _origin.Serve(Url, Document, cacheControl);

        Assert.Equal(TimeSpan.FromSeconds(seconds), (await FetchedAsync()).Lifetime);
    }

    [Fact]
    public async Task TheAgeOfAResponse_IsTakenFromItsLifetime()
    {
        _origin.Answer(Url, () =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(Document, Encoding.UTF8, "application/json"),
            };
            response.Headers.CacheControl = new CacheControlHeaderValue { MaxAge = TimeSpan.FromSeconds(120) };
            response.Headers.Age = TimeSpan.FromSeconds(100);
            return response;
        });

        Assert.Equal(TimeSpan.FromSeconds(20), (await FetchedAsync()).Lifetime);
    }

    /// <summary>
    /// The client's timeout ends only the wait for the headers, so a body that never arrives is ended by the fetch's
    /// own deadline, as a failure that may pass.
    /// </summary>
    [Fact]
    public async Task ABodyThatNeverArrives_EndsAtTheDeadline_AsAFailureThatMayPass()
    {
        _settings.FetchTimeout = TimeSpan.FromMilliseconds(200);
        _origin.Answer(Url, () => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StalledContent() });

        Assert.True((await FailedAsync()).MayPass);
    }

    [Fact]
    public async Task ABodyBrokenOffHalfWay_IsAFailureThatMayPass()
    {
        _origin.Answer(Url, () => new HttpResponseMessage(HttpStatusCode.OK) { Content = new BrokenContent() });

        Assert.True((await FailedAsync()).MayPass);
    }

    /// <summary>
    /// A destination the host named for its own services is not one an anonymous client identifier reaches.
    /// </summary>
    [Fact]
    public async Task ADestinationTheHostAllowsForItsServices_IsRefusedWithoutARequest()
    {
        _transport.AllowedDestinations = [new Uri("https://client.example.com")];
        _origin.Serve(Url, Document);

        Assert.False((await FailedAsync()).MayPass);
        Assert.Empty(_origin.Requests);
    }

    /// <summary>
    /// A JSON body whose bytes never come.
    /// </summary>
    private sealed class StalledContent : HttpContent
    {
        public StalledContent() => Headers.ContentType = new MediaTypeHeaderValue("application/json");

        protected override Task SerializeToStreamAsync(System.IO.Stream stream, TransportContext? context)
            => throw new NotSupportedException();

        protected override Task<System.IO.Stream> CreateContentReadStreamAsync(System.Threading.CancellationToken cancellationToken)
            => Task.FromResult<System.IO.Stream>(new StalledStream());

        protected override Task<System.IO.Stream> CreateContentReadStreamAsync()
            => Task.FromResult<System.IO.Stream>(new StalledStream());

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
    }

    private sealed class StalledStream : System.IO.MemoryStream
    {
        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer, System.Threading.CancellationToken cancellationToken = default)
        {
            await Task.Delay(System.Threading.Timeout.Infinite, cancellationToken);
            return 0;
        }
    }

    /// <summary>
    /// A JSON body whose connection breaks while it is read.
    /// </summary>
    private sealed class BrokenContent : HttpContent
    {
        public BrokenContent() => Headers.ContentType = new MediaTypeHeaderValue("application/json");

        protected override Task SerializeToStreamAsync(System.IO.Stream stream, TransportContext? context)
            => throw new System.IO.IOException("the connection was reset");

        protected override Task<System.IO.Stream> CreateContentReadStreamAsync()
            => throw new System.IO.IOException("the connection was reset");

        protected override Task<System.IO.Stream> CreateContentReadStreamAsync(System.Threading.CancellationToken cancellationToken)
            => throw new System.IO.IOException("the connection was reset");

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
    }

    /// <summary>
    /// A JSON body declaring no length, as a chunked response does, so only reading it tells its size.
    /// </summary>
    private sealed class UnsizedContent : HttpContent
    {
        private readonly byte[] _bytes;

        public UnsizedContent(string body)
        {
            _bytes = Encoding.UTF8.GetBytes(body);
            Headers.ContentType = new MediaTypeHeaderValue("application/json");
        }

        protected override Task SerializeToStreamAsync(System.IO.Stream stream, TransportContext? context)
            => stream.WriteAsync(_bytes, 0, _bytes.Length);

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
    }
}
