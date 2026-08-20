// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.SharedSignals.Model;

namespace Abblix.SharedSignals.Receiver.SecurityEvent;

/// <summary>
/// Builds a management client for one transmitter, over the transport a host configures.
/// </summary>
/// <remarks>
/// A stream client is half configuration and half connection: the transmitter's endpoints are
/// learned at run time from its metadata, while the connection they are spoken over is the host's
/// to shape - its timeouts, its resilience, its proxy. A factory is what lets both be true at
/// once. Constructing the client directly is still open to a caller who wants to bring its own
/// <c>HttpClient</c>; what this adds is the ordinary path, on which everything a host configured
/// for its other outbound clients already applies.
/// </remarks>
/// <param name="httpClientFactory">Supplies the configured transport by its published name.</param>
public sealed class StreamManagementClientFactory(IHttpClientFactory httpClientFactory)
{
    /// <summary>
    /// Creates a client for <paramref name="transmitter"/>.
    /// </summary>
    /// <param name="transmitter">
    /// The transmitter's configuration metadata, whose endpoints the client calls.</param>
    public StreamManagementClient Create(TransmitterConfiguration transmitter)
    {
        ArgumentNullException.ThrowIfNull(transmitter);

        return new StreamManagementClient(
            httpClientFactory.CreateClient(StreamManagementTransport.HttpClientName), transmitter);
    }
}
