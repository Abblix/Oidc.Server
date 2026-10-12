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

using Abblix.Oidc.Client.Features.Discovery;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Client.Features.EndSession;

/// <summary>
/// Builds RP-initiated logout addresses (OpenID Connect RP-Initiated Logout 1.0 section 2).
/// </summary>
/// <param name="metadataProvider">Supplies the endpoint address the provider published.</param>
/// <param name="clientOptions">Supplies this client's identifier.</param>
/// <param name="options">Supplies the post-logout address and language preferences.</param>
public sealed class EndSessionRequestBuilder(
    IProviderMetadataProvider metadataProvider,
    IOptions<OidcClientOptions> clientOptions,
    IOptions<EndSessionRequestOptions> options) : IEndSessionRequestBuilder
{
    /// <inheritdoc />
    public async Task<Uri> CreateAsync(
        string identityToken,
        string? state = null,
        string? logoutHint = null,
        CancellationToken cancellationToken = default)
    {
        var metadata = await metadataProvider.GetMetadataAsync(cancellationToken);

        if (metadata.EndSessionEndpoint is not { } endSessionEndpoint)
        {
            throw new EndSessionRequestException(
                $"The OpenID Provider '{metadata.Issuer}' publishes no end-session endpoint, so its side of "
                + "the session cannot be ended this way.");
        }

        // Whatever the endpoint already carries in its query is kept: a provider is free to publish one with
        // parameters of its own, and dropping them would break it.
        var endpoint = new Utils.UriBuilder(endSessionEndpoint);
        var parameters = endpoint.Query;

        parameters[Parameters.IdTokenHint] = identityToken;

        // Sent alongside the hint, which section 2 permits and constrains: "When both client_id and
        // id_token_hint are present, the OP MUST verify that the Client Identifier matches the one used when
        // issuing the ID Token." So it adds a check the provider makes on our behalf rather than an
        // ambiguity - and it is what lets a provider recognise the client at all when it accepts a logout
        // without a hint.
        parameters[Parameters.ClientId] = clientOptions.Value.ClientId;

        if (options.Value.PostLogoutRedirectUri is { } postLogoutRedirectUri)
            parameters[Parameters.PostLogoutRedirectUri] = RequireAbsolute(postLogoutRedirectUri);

        // Section 2 says of state that "if included in the logout request, the OP passes this value back to
        // the RP using the state parameter". It is the caller's to interpret, so it is only forwarded.
        if (!string.IsNullOrEmpty(state))
            parameters[Parameters.State] = state;

        if (!string.IsNullOrEmpty(logoutHint))
            parameters[Parameters.LogoutHint] = logoutHint;

        if (options.Value.UiLocales is { Count: > 0 } uiLocales)
            parameters[Parameters.UiLocales] = string.Join(' ', uiLocales);

        return endpoint.Uri;
    }

    /// <summary>
    /// Refuses a post-logout address that is not absolute.
    /// </summary>
    /// <remarks>
    /// The same requirement the redirection endpoint carries, and for the same reason: the provider does not
    /// resolve this address, it hands it to the browser, which resolves it from the provider's own page. A
    /// relative value therefore lands the user somewhere on the provider's site, having logged out
    /// successfully and never returned here.
    /// </remarks>
    private static string RequireAbsolute(Uri postLogoutRedirectUri)
    {
        if (!postLogoutRedirectUri.IsAbsoluteUri)
        {
            throw new EndSessionRequestException(
                $"{nameof(EndSessionRequestOptions)}."
                + $"{nameof(EndSessionRequestOptions.PostLogoutRedirectUri)} must be absolute. The browser "
                + "resolves it from the provider's page, so a relative address would leave the user there.");
        }

        return postLogoutRedirectUri.OriginalString;
    }
}
