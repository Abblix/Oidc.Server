// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// The HTTP transport pushed security event tokens travel on, to the endpoint a receiver configured for its stream.
/// </summary>
public static class PushDeliveryTransport
{
    /// <summary>
    /// The name the transport's client is registered under, published so a host can configure it without copying
    /// the string: <c>services.AddHttpClient(PushDeliveryTransport.HttpClientName)</c> reaches the same client the
    /// sender delivers over.
    /// </summary>
    /// <remarks>
    /// The value is the sender's name because this is a typed client, and that is the logical name
    /// <c>AddHttpClient&lt;TClient&gt;</c> gives it. A delivery pass makes one attempt per pending token, so a
    /// resilience pipeline here is what turns a transient receiver failure into a retry rather than a wait for the
    /// next pass.
    /// </remarks>
    public const string HttpClientName = nameof(PushDeliverySender);
}
