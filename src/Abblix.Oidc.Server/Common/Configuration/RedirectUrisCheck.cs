// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Refuses a tenant declaring a client whose redirect or post-logout redirect URI is not absolute, or uses a scheme
/// the user agent runs as script: javascript, data or vbscript.
/// </summary>
/// <remarks>
/// RFC 6749 section 3.1.2: "The redirection endpoint URI MUST be an absolute URI as defined by [RFC3986] Section 4.3".
/// OpenID Connect RP-Initiated Logout 1.0 calls the post-logout redirect URIs "URLs" without a rule of its own, and
/// they are held to the same one, since the user agent is sent to them the same way. A settings value the binder reads
/// as relative may still be a script URI to a browser, whose URL parser removes a tab or a newline anywhere in it and
/// a control character in front of it.
/// <para>
/// A response posted to a script URI runs in this server's origin, whichever kind of client names it. A web client the
/// host declares is otherwise held to no scheme rule, unlike a native app (<see cref="NativeClientsCheck"/>): the host
/// may send its own web clients wherever it trusts, so only the URIs that do not name a place to send the user agent
/// to, or that turn a redirect into script, are refused.
/// </para>
/// </remarks>
internal sealed class RedirectUrisCheck : ITenantsCheck
{
    private static readonly HashSet<string> ScriptSchemes = new(StringComparer.OrdinalIgnoreCase)
    {
        "javascript",
        "data",
        "vbscript",
    };

    /// <summary>
    /// Whether this check refuses <paramref name="uri"/> for every client, so another check of a client's redirect URIs
    /// leaves it to this one and judges only an absolute URI.
    /// </summary>
    /// <param name="uri">A redirect or post-logout redirect URI.</param>
    internal static bool Refuses(Uri? uri) => uri is not { IsAbsoluteUri: true } || ScriptSchemes.Contains(uri.Scheme);

    /// <inheritdoc />
    public IEnumerable<TenantRefusal> Check(IReadOnlyCollection<TenantDefinition> tenants, OidcOptions options)
        => TenantRefusal.EachOf(tenants, tenant => tenant.Clients.SelectMany(Failures));

    private static IEnumerable<string> Failures(ClientInfo client)
        => client.RedirectUris
            .Select(uri => (Member: nameof(ClientInfo.RedirectUris), Uri: uri))
            .Concat(client.PostLogoutRedirectUris
                .Select(uri => (Member: nameof(ClientInfo.PostLogoutRedirectUris), Uri: uri)))
            .Where(redirect => Refuses(redirect.Uri))
            .Select(redirect => Failure(client, redirect.Member, redirect.Uri));

    private static string Failure(ClientInfo client, string member, Uri? uri)
    {
        // A relative value is escaped in this refusal, so a tab, a newline or a control character it carries is shown
        // rather than written as it is
        if (uri is not { IsAbsoluteUri: true })
        {
            return $"The client '{client.ClientId}' has the {member} " +
                   $"'{Uri.EscapeDataString(uri?.OriginalString ?? string.Empty)}', which is not an absolute URI " +
                   $"(RFC 6749 section 3.1.2).";
        }

        return $"The client '{client.ClientId}' has the {member} '{uri}' of the {uri.Scheme} scheme, which runs as " +
               $"script in this server's origin when a response is posted to it.";
    }
}
