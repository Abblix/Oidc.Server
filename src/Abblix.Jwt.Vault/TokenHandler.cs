// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.Jwt.ExternalKeys;

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
        if (token is null && tokens.AuthenticationConfigured)
        {
            // A deployment that logs in has no token only while a failed login waits out its backoff. Sending
            // the request anyway draws Vault's answer to a request with no credentials, and that answer reads
            // as permanent - the caller would be told never to come back over a login that is retrying. The
            // condition is ours and it is temporary, so it is reported as what it is.
            throw new KeyCustodianUnavailableException(
                request.RequestUri?.AbsolutePath ?? "vault",
                "The vault login has no token yet; a failed login is waiting out its backoff.");
        }

        if (token is not null)
        {
            // Replace rather than add: the same request may be retried through this handler, and a second header
            // would make Vault reject it.
            request.Headers.Remove(TokenHeaderName);
            request.Headers.Add(TokenHeaderName, token);
        }

        var response = await base.SendAsync(request, cancellationToken);

        // A refusal of a token this deployment minted is about the credential, not the request, and the login
        // that minted it renews on its own schedule - so waiting is exactly what helps. Read from the status
        // alone it would be permanent, and the published keys would go with it. A deployment carrying a token
        // it did not mint has nothing that will replace it, so its refusal keeps the ordinary reading.
        if (token is not null &&
            tokens.AuthenticationConfigured &&
            response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
        {
            response.Dispose();
            throw new KeyCustodianUnavailableException(
                request.RequestUri?.AbsolutePath ?? "vault",
                "The vault refused the token this deployment logged in for.");
        }

        return response;
    }
}
