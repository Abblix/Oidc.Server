// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.SharedSignals.Receiver.SecurityEvent;

/// <summary>
/// The HTTP transport a receiver reads a transmitter's configuration metadata over
/// (SSF 1.0 Sections 7.2, 7.2.1).
/// </summary>
public static class TransmitterConfigurationTransport
{
    /// <summary>
    /// The name the transport's client is registered under, published so a host can configure it
    /// without copying the string:
    /// <c>services.AddHttpClient(TransmitterConfigurationTransport.HttpClientName)</c> reaches the
    /// same client the metadata is fetched with.
    /// </summary>
    /// <remarks>
    /// The value is the client's name because this is a typed client, and that is the logical name
    /// <c>AddHttpClient&lt;TClient&gt;</c> gives it. This is the first call a receiver makes to a
    /// transmitter it has never spoken to, so what a host configures here decides how a
    /// transmitter that is slow to wake is treated.
    /// </remarks>
    public const string HttpClientName = nameof(TransmitterConfigurationClient);
}
