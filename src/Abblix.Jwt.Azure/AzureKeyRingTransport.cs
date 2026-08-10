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

namespace Abblix.Jwt.Azure;

/// <summary>
/// The HTTP transport the key ring's blob calls travel on.
/// </summary>
/// <remarks>
/// Named rather than typed, because the store it serves takes a container client rather than an
/// <see cref="HttpClient"/>. The custodian's own client needs no such name: it is typed, reached as
/// <c>AddHttpClient&lt;KeyVaultClient&gt;()</c>.
/// </remarks>
public static class AzureKeyRingTransport
{
    /// <summary>
    /// The name the transport's client is registered under, published so a host can configure it without copying
    /// the string: <c>services.AddHttpClient(AzureKeyRingTransport.HttpClientName)</c> reaches the same client the
    /// ring resolves, and whatever it chains - a resilience pipeline, a proxy, a client certificate - applies to
    /// every blob call.
    /// </summary>
    /// <remarks>
    /// The credential authenticates over a transport of its own, so what a host chains here does not cover the
    /// token requests.
    /// </remarks>
    public const string HttpClientName = "Abblix.Jwt.Azure.KeyRing";
}
