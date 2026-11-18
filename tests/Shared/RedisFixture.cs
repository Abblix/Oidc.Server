// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using StackExchange.Redis;
using Testcontainers.Redis;

namespace Abblix.Tests.Shared;

/// <summary>
/// A real Redis server in a container of its own, so the stores are measured against the server a
/// deployment runs rather than against a protocol-compatible stand-in whose scripting, WATCH and
/// transaction behaviour are its own.
/// </summary>
/// <remarks>
/// The image is the version the cluster runs, pinned by digest so a retagged image cannot change what
/// the tests measure. Starting it needs a Docker daemon, which the GitHub-hosted runners and a
/// developer machine with Docker running both have.
/// </remarks>
public sealed class RedisFixture : IDisposable
{
    private const string Image =
        "redis:8.10.2-alpine@sha256:9f8d2d789b9a1d1e3f283f979aa9cbf393373806472e1ccd460e2f9c869b833b";

    private readonly RedisContainer _container;

    public RedisFixture()
    {
        _container = new RedisBuilder(Image).Build();
        _container.StartAsync().GetAwaiter().GetResult();
        Connection = CreateConnection();
    }

    public ConnectionMultiplexer Connection { get; }

    /// <summary>
    /// Opens ANOTHER connection to the same server, for the tests that need two replicas rather than
    /// two objects.
    /// </summary>
    /// <remarks>
    /// Two instances sharing one multiplexer are indistinguishable from one instance: the client holds
    /// the physical connection for the duration of a transaction, so their commands never actually
    /// interleave at the server. A test built that way measures concurrency it has excluded - which is
    /// exactly the blind spot that let a stream-store defect through, invisible from one multiplexer
    /// and present in the majority of operations from two.
    /// </remarks>
    public ConnectionMultiplexer CreateConnection()
        => ConnectionMultiplexer.Connect(_container.GetConnectionString());

    public void Dispose()
    {
        Connection.Dispose();
        _container.DisposeAsync().AsTask().GetAwaiter().GetResult();
    }
}
