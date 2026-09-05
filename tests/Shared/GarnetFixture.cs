// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System;
using System.Net;
using System.Net.Sockets;
using Garnet;
using Garnet.server;
using StackExchange.Redis;

namespace Abblix.Tests.Shared;

/// <summary>
/// A real Redis-protocol server inside the test process: embedded Garnet on a loopback port
/// picked at startup. No container, no external service - and still an actual server, which is
/// what lets a test witness the server-side atomicity these implementations exist for.
/// </summary>
/// <remarks>
/// Shared rather than owned by one suite, because every Redis-backed implementation needs the
/// same thing and a second copy of an embedded server is a second set of startup options to keep
/// in step - the kind of divergence that surfaces as one suite proving something the other cannot.
/// </remarks>
public sealed class GarnetFixture : IDisposable
{
    private readonly GarnetServer _server;

    public GarnetFixture()
    {
        var endPoint = new IPEndPoint(IPAddress.Loopback, FreeTcpPort());
        _server = new GarnetServer(new GarnetServerOptions
        {
            EndPoints = [endPoint],

            // The stream store replaces what a stream is with one server-side script, so the fixture
            // has to speak EVAL. LuaOptions is not optional beside the flag: the server dereferences
            // it while starting and fails with a null reference if only the flag is set.
            EnableLua = true,
            LuaOptions = new LuaOptions(),
        });
        _server.Start();
        _endPoint = endPoint;

        Connection = CreateConnection();
    }

    private readonly IPEndPoint _endPoint;

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
        => ConnectionMultiplexer.Connect(new ConfigurationOptions { EndPoints = { _endPoint } });

    public void Dispose()
    {
        Connection.Dispose();
        _server.Dispose();
    }

    /// <summary>
    /// Lets the operating system pick a free port and releases it for Garnet to take: the gap
    /// is a race in principle, and in practice the port stays ours for the microseconds the
    /// handover takes.
    /// </summary>
    private static int FreeTcpPort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }
}
