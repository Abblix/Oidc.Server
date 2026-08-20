// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Jwt.Vault;

/// <summary>
/// Presents the Vault token on every request, reading it fresh each time.
/// </summary>
/// <remarks>
/// Stamping the header once, when the client is built, would pin the token for the process lifetime: the typed
/// client is held by singletons and its handler chain never rotates, so the configure delegate runs exactly once.
/// Asking <see cref="TokenSource"/> per request is what lets the token be renewed, replaced, or rotated by the
/// host without restarting the process - and the ask itself is what drives the refresh, because the source
/// refreshes on use. A request marked <see cref="SelfAuthenticated"/> passes through untouched: the source's own
/// login and renewal calls travel through this same handler, and asking the source from inside its refresh
/// would wait on the very work in flight.
/// </remarks>
internal sealed class TokenHandler(TokenSource tokens) : DelegatingHandler
{
    /// <summary>Vault's authentication header, and the name to keep out of logs.</summary>
    internal const string TokenHeaderName = "X-Vault-Token";

    /// <summary>
    /// Marks a request that manages its own authentication: a login, which is unauthenticated by design,
    /// or a renewal, which carries the exact token being renewed. The handler neither attaches a token
    /// nor asks the source for one - the ask would recurse into the refresh that sent the request.
    /// </summary>
    internal static readonly HttpRequestOptionsKey<bool> SelfAuthenticated = new("Abblix.Jwt.Vault.SelfAuthenticated");

    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        if (request.Options.TryGetValue(SelfAuthenticated, out var selfAuthenticated) && selfAuthenticated)
            return await base.SendAsync(request, cancellationToken);

        var token = await tokens.GetTokenAsync(cancellationToken);
        if (token is not null)
        {
            // Replace rather than add: the same request may be retried through this handler, and a second header
            // would make Vault reject it.
            request.Headers.Remove(TokenHeaderName);
            request.Headers.Add(TokenHeaderName, token);
        }

        return await base.SendAsync(request, cancellationToken);
    }
}
