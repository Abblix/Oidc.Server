// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.SecureHttpFetch;

/// <summary>
/// The HTTP transport the server's metadata fetches travel on: a client's key set, a request object behind a
/// "request_uri", a software statement's issuer keys.
/// </summary>
public static class SecureFetchTransport
{
    /// <summary>
    /// The name the transport's client is registered under, published so a host can configure it without copying
    /// the string: <c>services.AddHttpClient(SecureFetchTransport.HttpClientName)</c> reaches the same client the
    /// fetcher resolves.
    /// </summary>
    /// <remarks>
    /// The value is the contract's name because this is a typed client, and that is the logical name
    /// <c>AddHttpClient&lt;TClient, TImplementation&gt;</c> gives it. Whatever a host chains runs outside the SSRF
    /// validation, which is this client's primary handler, so every retried attempt is validated afresh.
    /// </remarks>
    public const string HttpClientName = nameof(ISecureHttpFetcher);
}
