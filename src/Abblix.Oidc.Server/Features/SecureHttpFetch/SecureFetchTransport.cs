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
