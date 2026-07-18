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

using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Vault;

/// <summary>
/// Presents the Vault token on every request, reading it fresh each time.
/// </summary>
/// <remarks>
/// Stamping the header once, when the client is built, would pin the token for the process lifetime: the typed
/// client is held by singletons and its handler chain never rotates, so the configure delegate runs exactly once.
/// That is only workable with a long-lived token, which is the posture the README tells operators not to use.
/// Reading through <see cref="IOptionsMonitor{TOptions}"/> per request lets a token minted by AppRole or
/// Kubernetes auth be renewed and picked up, without restarting the process.
/// </remarks>
internal sealed class TokenHandler(IOptionsMonitor<VaultTransitOptions> options) : DelegatingHandler
{
    /// <summary>Vault's authentication header, and the name to keep out of logs.</summary>
    internal const string TokenHeaderName = "X-Vault-Token";

    /// <inheritdoc />
    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var token = options.CurrentValue.Token;
        if (!string.IsNullOrWhiteSpace(token))
        {
            // Replace rather than add: the same request may be retried through this handler, and a second header
            // would make Vault reject it.
            request.Headers.Remove(TokenHeaderName);
            request.Headers.Add(TokenHeaderName, token);
        }

        return base.SendAsync(request, cancellationToken);
    }
}
