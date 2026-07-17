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

namespace Abblix.Oidc.Server.Vault;

/// <summary>
/// The HTTP transport to a Vault / OpenBao server, as the engine-facing classes see it: hand it a method, a path
/// and a body, and get the parsed response back.
/// </summary>
/// <remarks>
/// It carries no notion of an engine. Which mount, which path, and what a given status means are the caller's,
/// because those are exactly what differ between Transit and KV - and what the two have in common is only the
/// wire. One transport per server, not per engine: the custodian and the key ring talk to the same Vault with the
/// same token, so they share one connection pool and one place where the auth header, its redaction and the
/// connection lifetime are settled.
/// </remarks>
internal interface IApiClient
{
    /// <summary>
    /// Sends a request and hands back what Vault answered, whatever the status. A failure status is not thrown
    /// on, because to some callers it is the answer: a lost cas race, a secret that is not there, a rejected
    /// ciphertext. A caller that wants the opposite says so with
    /// <see cref="Response.EnsureSuccess"/>.
    /// </summary>
    /// <param name="method">The HTTP method, including Vault's own LIST.</param>
    /// <param name="path">The path under the server's <c>/v1/</c> root, mount included.</param>
    /// <param name="body">The request body, serialized as JSON, or null for a request without one.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>What Vault answered. The caller owns it and disposes it.</returns>
    Task<Response> SendAsync(
        HttpMethod method,
        string path,
        object? body,
        CancellationToken cancellationToken);
}
