// Abblix OIDC Client Library
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

namespace Abblix.Oidc.Client.UnitTests.Features.Discovery;

/// <summary>
/// An <see cref="IHttpClientFactory"/> that hands out clients over a single stub handler, whatever name is
/// asked for.
/// </summary>
public sealed class StubHttpClientFactory : IHttpClientFactory
{
    private readonly HttpMessageHandler _handler;

    /// <summary>
    /// Creates the factory over the handler every client will send through.
    /// </summary>
    public StubHttpClientFactory(HttpMessageHandler handler) => _handler = handler;

    /// <inheritdoc />
    /// <remarks>
    /// The handler is deliberately not disposed with the client: a test keeps asserting against the recorded
    /// requests after the client is gone.
    /// </remarks>
    public HttpClient CreateClient(string name) => new(_handler, disposeHandler: false);
}
