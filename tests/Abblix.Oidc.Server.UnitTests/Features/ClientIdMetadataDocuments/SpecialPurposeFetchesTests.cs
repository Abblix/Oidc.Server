// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientIdMetadataDocuments;

/// <summary>
/// The server's fetches for a client resolved from its metadata document hold to the special-purpose address registries
/// as written (draft-ietf-oauth-client-id-metadata-document section 10.7), the NAT64 prefix included, where the same
/// fetch for any other client lets NAT64 reach the public address it carries.
/// </summary>
public class SpecialPurposeFetchesTests
{
    private const string JwksUri = "https://keys.example.com/jwks";

    /// <summary>The well-known NAT64 prefix carrying a public IPv4 address, 8.8.8.8.</summary>
    private static readonly IPAddress Nat64OfPublic = IPAddress.Parse("64:ff9b::808:808");

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public async Task AKeySetBehindNat64_IsFetchedOnlyForAClientNotResolvedFromADocument(bool fromDocument, bool fetched)
    {
        var origin = new KeySetOrigin();
        await using var provider = Services(origin).BuildServiceProvider();
        var keys = new ClientKeysProvider(NullLogger<ClientKeysProvider>.Instance, provider);
        var client = new ClientInfo("client")
        {
            JwksUri = new Uri(JwksUri),
            ResolvedFromMetadataDocument = fromDocument,
        };

        var found = await keys.GetSigningKeys(client).ToArrayAsync(TestContext.Current.CancellationToken);

        Assert.Equal(fetched, found.Length > 0);
        Assert.Equal(fetched, origin.Reached);
    }

    /// <summary>
    /// One key set behind NAT64, named by a registered client and by a document client in either order: the document
    /// client is refused whether the set is already held or not, and its refusal, held for the refetch interval, does
    /// not stand in for the registered client's fetch, so whoever publishes a document naming another client's key set
    /// cannot cut that client off.
    /// </summary>
    [Theory]
    [InlineData(true, false)]
    [InlineData(false, false)]
    [InlineData(true, true)]
    [InlineData(false, true)]
    public async Task AKeySetTwoKindsOfClientShare_IsServedOnlyToTheRegisteredOne(bool documentClientFirst, bool refetch)
    {
        var origin = new KeySetOrigin();
        await using var provider = Services(origin).BuildServiceProvider();
        var keys = new ClientKeysProvider(NullLogger<ClientKeysProvider>.Instance, provider);
        var registered = new ClientInfo("registered") { JwksUri = new Uri(JwksUri) };
        var fromDocument = new ClientInfo("https://client.example.com/metadata.json")
        {
            JwksUri = new Uri(JwksUri),
            ResolvedFromMetadataDocument = true,
        };

        var found = new Dictionary<ClientInfo, int>();
        foreach (var client in documentClientFirst ? new[] { fromDocument, registered } : [registered, fromDocument])
        {
            var set = await keys.GetSigningKeys(client, refetch).ToArrayAsync(TestContext.Current.CancellationToken);
            found[client] = set.Length;
        }

        Assert.Equal(0, found[fromDocument]);
        Assert.Equal(1, found[registered]);
        Assert.Equal(1, origin.Requests);
    }

    [Fact]
    public async Task OutsideAScope_TheHandlerJudgesNat64ByItsIPv4Address_AndInsideOneRefusesIt()
    {
        var origin = new KeySetOrigin();
        await using var provider = Services(origin).BuildServiceProvider();
        using var invoker = new HttpMessageInvoker(provider.GetRequiredService<SsrfValidatingHttpMessageHandler>());

        Assert.Null(await Record.ExceptionAsync(() => FetchKeySetAsync(invoker)));
        using (SpecialPurposeFetches.Enter())
            await Assert.ThrowsAsync<HttpRequestException>(() => FetchKeySetAsync(invoker));

        Assert.Null(await Record.ExceptionAsync(() => FetchKeySetAsync(invoker)));
    }

    private static Task<HttpResponseMessage> FetchKeySetAsync(HttpMessageInvoker invoker)
        => invoker.SendAsync(new HttpRequestMessage(HttpMethod.Get, JwksUri), TestContext.Current.CancellationToken);

    /// <summary>
    /// The server's outbound fetching with the name of every host resolving to <see cref="Nat64OfPublic"/>, and the
    /// network behind the SSRF validation replaced by <paramref name="origin"/>.
    /// </summary>
    private static ServiceCollection Services(KeySetOrigin origin)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();

        // Registered before the server's own, which then leaves it in place
        services.AddTransient(serviceProvider =>
        {
            var handler = new SsrfValidatingHttpMessageHandler(
                serviceProvider.GetRequiredService<IOptions<SecureHttpFetchOptions>>(),
                serviceProvider.GetRequiredService<ISecureUriValidator>(),
                (_, _) => Task.FromResult(new[] { Nat64OfPublic }));
            handler.InnerHandler!.Dispose();
            handler.InnerHandler = origin;
            return handler;
        });
        services.AddSecureHttpFetch();
        return services;
    }

    /// <summary>
    /// A client's key set, served wherever the request reaches.
    /// </summary>
    private sealed class KeySetOrigin : HttpMessageHandler
    {
        private static readonly string KeySet = JsonSerializer.Serialize(new JsonWebKeySet(
        [
            JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256).Sanitize(includePrivateKeys: false),
        ]));

        private int _requests;

        public int Requests => _requests;

        public bool Reached => Requests > 0;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _requests);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(KeySet, Encoding.UTF8, "application/json"),
            });
        }
    }
}
