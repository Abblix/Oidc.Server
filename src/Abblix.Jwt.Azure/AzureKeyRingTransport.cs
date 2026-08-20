// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
