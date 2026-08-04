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
using System.Net.Sockets;
using Garnet;
using Garnet.server;
using StackExchange.Redis;

namespace Abblix.SharedSignals.Redis.UnitTests;

/// <summary>
/// A real Redis-protocol server inside the test process: embedded Garnet on a loopback port
/// picked at startup. No container, no external service - and still an actual server, which is
/// what lets these tests witness the server-side atomicity the outbox exists for.
/// </summary>
public sealed class GarnetFixture : IDisposable
{
    private readonly GarnetServer _server;

    public GarnetFixture()
    {
        var endPoint = new IPEndPoint(IPAddress.Loopback, FreeTcpPort());
        _server = new GarnetServer(new GarnetServerOptions
        {
            EndPoints = [endPoint],
        });
        _server.Start();

        Connection = ConnectionMultiplexer.Connect(
            new ConfigurationOptions { EndPoints = { endPoint } });
    }

    public ConnectionMultiplexer Connection { get; }

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
