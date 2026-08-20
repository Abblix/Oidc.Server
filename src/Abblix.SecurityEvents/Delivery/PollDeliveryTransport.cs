// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.SecurityEvents.Delivery;

/// <summary>
/// The HTTP transport a receiver polls a transmitter's pending tokens over (RFC 8936).
/// </summary>
public static class PollDeliveryTransport
{
    /// <summary>
    /// The name the transport's client is registered under, published so a host can configure it
    /// without copying the string: <c>services.AddHttpClient(PollDeliveryTransport.HttpClientName)</c>
    /// reaches the same client the poll client speaks over.
    /// </summary>
    /// <remarks>
    /// The value is the client's name because this is a typed client, and that is the logical name
    /// <c>AddHttpClient&lt;TClient&gt;</c> gives it. A poll may be a long one the transmitter holds
    /// open, so the timeout a host sets here is the one that decides how long it waits.
    /// </remarks>
    public const string HttpClientName = nameof(PollClient);
}
