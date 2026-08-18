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

namespace Abblix.Jwt.Vault;

/// <summary>
/// Presents the Vault token on every request, reading it fresh each time.
/// </summary>
/// <remarks>
/// Stamping the header once, when the client is built, would pin the token for the process lifetime: the typed
/// client is held by singletons and its handler chain never rotates, so the configure delegate runs exactly once.
/// Reading through <see cref="TokenSource"/> per request lets a token minted by the package's own login, or one
/// the host rotates through configuration, take effect without restarting the process. When the package logs in
/// itself and no token exists yet, the request waits for the first login instead of failing without one - except
/// a request marked <see cref="AnonymousRequest"/>, which is how the login request itself passes through without
/// deadlocking on the token it is about to mint.
/// </remarks>
internal sealed class TokenHandler(TokenSource tokens) : DelegatingHandler
{
    /// <summary>Vault's authentication header, and the name to keep out of logs.</summary>
    internal const string TokenHeaderName = "X-Vault-Token";

    /// <summary>
    /// Marks a request to an unauthenticated Vault path. No token is attached - Vault ignores one there, so
    /// sending it would only spread the credential - and, decisively, the request does not wait for the first
    /// login: the login request itself travels through this same handler.
    /// </summary>
    internal static readonly HttpRequestOptionsKey<bool> AnonymousRequest = new("Abblix.Jwt.Vault.Anonymous");

    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        if (request.Options.TryGetValue(AnonymousRequest, out var anonymous) && anonymous)
            return await base.SendAsync(request, cancellationToken);

        var token = tokens.Current;
        if (token is null && tokens.AuthenticationConfigured)
        {
            // The caller's cancellation bounds this caller's WAIT only; the login it waits for runs under the
            // lifecycle service and survives any one caller giving up.
            await tokens.FirstLoginCompleted.WaitAsync(cancellationToken);
            token = tokens.Current;
        }

        if (!string.IsNullOrWhiteSpace(token))
        {
            // Replace rather than add: the same request may be retried through this handler, and a second header
            // would make Vault reject it.
            request.Headers.Remove(TokenHeaderName);
            request.Headers.Add(TokenHeaderName, token);
        }

        return await base.SendAsync(request, cancellationToken);
    }
}
