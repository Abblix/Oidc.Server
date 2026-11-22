// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Tests.Shared;
using StackExchange.Redis;
using Testcontainers.Redis;
using Xunit;

[assembly: AssemblyFixture(typeof(RedisFixture))]

namespace Abblix.Tests.Shared;

/// <summary>
/// A real Redis server in a container, one per test process, so the stores are measured against the server a
/// deployment runs rather than against a protocol-compatible stand-in whose scripting, WATCH and transaction
/// behaviour are its own.
/// </summary>
/// <remarks>
/// The image is the version the cluster runs, pinned by digest so a retagged image cannot change what the tests
/// measure. Starting it needs a Docker daemon, which the GitHub-hosted runners and a developer machine with Docker
/// running both have.
/// <para>
/// Every test in the process shares this one server, since each container started is one more for Docker
/// Desktop's VM to keep answering while every test project loads the CPU at once. Sharing holds only while each
/// test writes under keys no other test uses - its own receiver, stream or tenant partition - and never empties
/// the server, since classes run in parallel.
/// </para>
/// <para>
/// The container starts when a test first asks for a connection, not with the process: xunit creates an assembly
/// fixture before any test runs, and most tests of a project linking this file need no Redis at all.
/// </para>
/// </remarks>
public sealed class RedisFixture : IDisposable
{
    private const string Image =
        "redis:8.10.2-alpine@sha256:9f8d2d789b9a1d1e3f283f979aa9cbf393373806472e1ccd460e2f9c869b833b";

    private readonly Lazy<RedisContainer> _container = new(StartContainer);
    private readonly Lazy<ConnectionMultiplexer> _connection;

    public RedisFixture()
    {
        _connection = new Lazy<ConnectionMultiplexer>(CreateConnection);
    }

    public ConnectionMultiplexer Connection => _connection.Value;

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
        => ConnectionMultiplexer.Connect(_container.Value.GetConnectionString());

    public void Dispose()
    {
        if (_connection.IsValueCreated)
            _connection.Value.Dispose();

        if (_container.IsValueCreated)
            _container.Value.DisposeAsync().AsTask().GetAwaiter().GetResult();
    }

    private static RedisContainer StartContainer()
    {
        var container = new RedisBuilder(Image).Build();
        container.StartAsync().GetAwaiter().GetResult();
        return container;
    }
}
