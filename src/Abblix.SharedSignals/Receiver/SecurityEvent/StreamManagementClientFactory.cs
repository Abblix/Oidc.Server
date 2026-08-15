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
