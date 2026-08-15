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
