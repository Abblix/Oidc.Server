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

// Spelled out rather than left to ImplicitUsings, because this file is compiled into suites that do not enable it.
using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http.Resilience;
using Polly;

// A namespace of its own, not the namespace of whichever suite it was last edited from: this file is linked into
// the test project of every package that owns an outbound client, and naming one of them there makes the other
// four import a stranger.
namespace Abblix.Tests.Shared;

/// <summary>
/// What a host writes to make one of this library's outbound clients resilient, and the origin that proves it ran.
/// </summary>
/// <remarks>
/// Shared by link across the test projects of every package that owns an outbound client, so each asserts the same
/// promise in the same words: the promise is one, and a per-package rewrite of it would drift.
/// </remarks>
public static class HostResilienceProbe
{
    /// <summary>
    /// Adds the resilience pipeline a typical host adds - retries and a circuit breaker among them - with the retry
    /// delay removed so a test does not pay the production backoff.
    /// </summary>
    /// <param name="builder">The client builder returned by <c>AddHttpClient</c>.</param>
    /// <returns>The same builder, for chaining.</returns>
    public static IHttpClientBuilder AddResilienceOfATypicalHost(this IHttpClientBuilder builder)
    {
        builder.AddStandardResilienceHandler(options =>
        {
            options.Retry.MaxRetryAttempts = 2;
            options.Retry.Delay = TimeSpan.Zero;
            options.Retry.BackoffType = DelayBackoffType.Constant;
            options.Retry.UseJitter = false;
        });

        return builder;
    }
}
