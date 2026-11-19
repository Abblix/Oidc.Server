// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Globalization;
using System.Text;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Refuses a tenant declaring a client whose redirect or post-logout redirect URI is not absolute, includes a fragment,
/// or uses a scheme the user agent runs as script: javascript, data or vbscript.
/// </summary>
/// <remarks>
/// RFC 6749 section 3.1.2: "The redirection endpoint URI MUST be an absolute URI as defined by [RFC3986] Section 4.3",
/// and "The endpoint URI MUST NOT include a fragment component". OpenID Connect RP-Initiated Logout 1.0 calls the
/// post-logout redirect URIs "URLs" without a rule of its own, and they are held to the same two, as dynamic
/// registration holds them, since the user agent is sent to them the same way. A settings value the binder reads as
/// relative may still be a script URI to a browser, whose URL parser removes a tab or a newline anywhere in it and a
/// control character in front of it.
/// <para>
/// A response posted to a script URI runs in this server's origin, whichever kind of client names it. A web client the
/// host declares is otherwise held to no scheme rule, unlike a native app (<see cref="NativeClientsCheck"/>): the host
/// may send its own web clients wherever it trusts, so only the URIs that do not name a redirection endpoint, or that
/// turn a redirect into script, are refused.
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
    internal static bool Refuses(Uri? uri)
        => uri is not { IsAbsoluteUri: true } || uri.Fragment.HasValue() || ScriptSchemes.Contains(uri.Scheme);

    /// <summary>
    /// <paramref name="uri"/> as a refusal shows it: as the settings spell it, with each control, format or whitespace
    /// character other than a space percent-encoded, so the value cannot break or hide inside the logged line.
    /// </summary>
    /// <param name="uri">A redirect or post-logout redirect URI, or null for an empty settings value.</param>
    internal static string Shown(Uri? uri)
    {
        var value = uri?.OriginalString ?? string.Empty;
        var shown = new StringBuilder(value.Length);
        foreach (var rune in value.EnumerateRunes())
        {
            if (IsInvisible(rune))
                shown.Append(Uri.EscapeDataString(rune.ToString()));
            else
                shown.Append(rune.ToString());
        }

        return shown.ToString();
    }

    private static bool IsInvisible(Rune rune)
        => Rune.IsControl(rune)
           || (Rune.IsWhiteSpace(rune) && rune.Value != ' ')
           || Rune.GetUnicodeCategory(rune) == UnicodeCategory.Format;

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
        var named = $"The client '{client.ClientId}' has the {member} '{Shown(uri)}'";

        if (uri is not { IsAbsoluteUri: true })
            return $"{named}, which is not an absolute URI (RFC 6749 section 3.1.2).";

        if (uri.Fragment.HasValue())
            return $"{named}, which includes a fragment (RFC 6749 section 3.1.2).";

        return $"{named} of the {uri.Scheme} scheme, which runs as script in this server's origin when a response is " +
               $"posted to it.";
    }
}
