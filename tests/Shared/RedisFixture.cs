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
/// fixture before any test runs, and most tests of a project linking this file need no Redis at all. A start or a
/// connection that fails is not kept, so the next test asks Docker again: one stall of Docker Desktop's VM then
/// costs the test it hit, not every Redis test left in the process.
/// </para>
/// </remarks>
public sealed class RedisFixture : IDisposable
{
    private const string Image =
        "redis:8.10.2-alpine@sha256:9f8d2d789b9a1d1e3f283f979aa9cbf393373806472e1ccd460e2f9c869b833b";

    private readonly Lock _gate = new();
    private RedisContainer? _container;
    private ConnectionMultiplexer? _connection;

    public ConnectionMultiplexer Connection
    {
        get
        {
            lock (_gate)
                return _connection ??= Connect(StartedContainer());
        }
    }

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
    {
        RedisContainer container;
        lock (_gate)
            container = StartedContainer();

        return Connect(container);
    }

    public void Dispose()
    {
        _connection?.Dispose();
        _container?.DisposeAsync().AsTask().GetAwaiter().GetResult();
    }

    /// <summary>
    /// The running container, started on the first call. Called under <see cref="_gate"/>, so tests asking at once
    /// wait for one start rather than each starting a container of its own.
    /// </summary>
    private RedisContainer StartedContainer()
    {
        if (_container is not null)
            return _container;

        // A container whose start failed is left to the Testcontainers reaper: removing it here would call Docker
        // again in the same stall, under the gate, and a failure of that call would hide why the start failed
        var container = new RedisBuilder(Image).Build();
        container.StartAsync().GetAwaiter().GetResult();
        return _container = container;
    }

    private static ConnectionMultiplexer Connect(RedisContainer container)
        => ConnectionMultiplexer.Connect(container.GetConnectionString());
}
