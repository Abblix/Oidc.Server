// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.SharedSignals.Receiver.SecurityEvent;

/// <summary>
/// The HTTP transport a receiver manages its streams over: the Event Stream Management API of one
/// transmitter (SSF 1.0 Section 8.1).
/// </summary>
public static class StreamManagementTransport
{
    /// <summary>
    /// The name the transport's client is registered under, published so a host can configure it
    /// without copying the string:
    /// <c>services.AddHttpClient(StreamManagementTransport.HttpClientName)</c> reaches the same
    /// client stream calls are spoken over.
    /// </summary>
    /// <remarks>
    /// A NAMED client rather than a typed one, because the client this feeds is not built by the
    /// factory: <see cref="StreamManagementClient"/> also takes the transmitter's configuration,
    /// which is data a receiver learns at run time. <see cref="StreamManagementClientFactory"/>
    /// pairs the two, and the name exists so a host still reaches the transport the way it reaches
    /// every other.
    /// </remarks>
    public const string HttpClientName = nameof(StreamManagementClient);
}
