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
using Abblix.Jwt;
using Abblix.Tests.Shared;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.SecurityEvents.UnitTests;

/// <summary>
/// Key-set fetches must accept a resilience pipeline from the host, in the one call that covers every client
/// without naming any: an issuer's endpoint is somebody else's infrastructure, and a fetch that fails takes a
/// token's validation down with it.
/// </summary>
public class JwksFetchResilienceTests
{
    /// <summary>
    /// Driven through the real consumer: the resolver fetches a key set through the flaky origin and only succeeds
    /// because the host's retry absorbed the two failures. Anchoring on <see cref="IIssuerKeyResolver"/> rather
    /// than on a handler read back by the same name is what makes a wrong <see cref="JwksTransport.HttpClientName"/>
    /// fail this test: the resolver would then fetch through a client the stub never configured.
    /// </summary>
    [Fact]
    public async Task OneHostCall_MakesTheResolversKeySetFetchResilient()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();

        // The whole of what a host writes, naming nothing this library owns.
        services.ConfigureHttpClientDefaults(builder => builder.AddResilienceOfATypicalHost());

        services.AddSecurityEvents();
        services.AddJwksKeyResolution();

        var issuer = new FlakyKeySetOrigin(failuresBeforeSuccess: 2);
        services.AddHttpClient(JwksTransport.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => issuer);

        await using var provider = services.BuildServiceProvider();
        var resolver = provider.GetRequiredService<IIssuerKeyResolver>();

        var keys = new List<JsonWebKey>();
        await foreach (var key in resolver.ResolveSigningKeysAsync(
                           "https://issuer.test", cancellationToken: TestContext.Current.CancellationToken))
        {
            keys.Add(key);
        }

        // The fetch completed, which it could only do after two failures were retried away.
        Assert.Empty(keys);
        Assert.Equal(3, issuer.Requests);
    }

    /// <summary>Fails a set number of times, then answers with an empty but well-formed JWK Set.</summary>
    private sealed class FlakyKeySetOrigin(int failuresBeforeSuccess) : HttpMessageHandler
    {
        public int Requests { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Requests++;
            if (Requests <= failuresBeforeSuccess)
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"keys":[]}""", Encoding.UTF8, "application/json"),
            });
        }
    }
}
