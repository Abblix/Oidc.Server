// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
