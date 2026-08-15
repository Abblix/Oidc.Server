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
