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

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Utils;
using Microsoft.Extensions.Caching.Memory;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.SecureHttpFetch;

/// <summary>
/// Verifies that the caching decorator actually spares the network, and that its lifetime is the one it was
/// constructed with. Asserting the type of the registered decorator is not enough: an instance built with a
/// zero lifetime is the same type and caches nothing.
/// </summary>
public class CachingSecureHttpFetcherDecoratorTests
{
    private static readonly Uri KeySetUri = new("https://issuer.example.com/.well-known/jwks.json");

    private static (CachingSecureHttpFetcherDecorator Decorator, Mock<ISecureHttpFetcher> Inner) Create(
        TimeSpan cacheDuration)
    {
        var inner = new Mock<ISecureHttpFetcher>(MockBehavior.Strict);
        var cache = new MemoryCache(new MemoryCacheOptions());
        return (new CachingSecureHttpFetcherDecorator(inner.Object, cache, cacheDuration), inner);
    }

    /// <summary>
    /// A second fetch of the same document is served from the cache: the inner fetcher is called once. This is
    /// the property the registration exists for, and the one a type assertion cannot see.
    /// </summary>
    [Fact]
    public async Task SecondFetchOfTheSameUri_DoesNotReachTheInnerFetcher()
    {
        var (decorator, inner) = Create(TimeSpan.FromHours(1));
        inner
            .Setup(f => f.FetchAsync<string>(KeySetUri))
            .ReturnsAsync(Result<string, OidcError>.Success("key-set"));

        await decorator.FetchAsync<string>(KeySetUri);
        await decorator.FetchAsync<string>(KeySetUri);

        inner.Verify(f => f.FetchAsync<string>(KeySetUri), Times.Once);
    }

    /// <summary>
    /// The lifetime comes from the instance, so a decorator built with a zero duration holds nothing and every
    /// fetch reaches the network. This is what separates one consumer's cached fetcher from another's, and it
    /// is why the duration is a constructor argument rather than a parameter of the transport contract.
    /// </summary>
    [Fact]
    public async Task ZeroCacheDuration_ReachesTheInnerFetcherEveryTime()
    {
        var (decorator, inner) = Create(TimeSpan.Zero);
        inner
            .Setup(f => f.FetchAsync<string>(KeySetUri))
            .ReturnsAsync(Result<string, OidcError>.Success("key-set"));

        await decorator.FetchAsync<string>(KeySetUri);
        await decorator.FetchAsync<string>(KeySetUri);

        inner.Verify(f => f.FetchAsync<string>(KeySetUri), Times.Exactly(2));
    }

    /// <summary>
    /// A failed fetch is not cached, so a transient failure does not lock the consumer out for the whole
    /// lifetime: the next call tries again.
    /// </summary>
    [Fact]
    public async Task FailedFetch_IsNotCached()
    {
        var (decorator, inner) = Create(TimeSpan.FromHours(1));
        inner
            .Setup(f => f.FetchAsync<string>(KeySetUri))
            .ReturnsAsync(new OidcError(ErrorCodes.ServerError, "unreachable"));

        await decorator.FetchAsync<string>(KeySetUri);
        await decorator.FetchAsync<string>(KeySetUri);

        inner.Verify(f => f.FetchAsync<string>(KeySetUri), Times.Exactly(2));
    }
}
