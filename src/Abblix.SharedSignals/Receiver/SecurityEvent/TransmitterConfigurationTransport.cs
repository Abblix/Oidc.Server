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
