// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Globalization;
using System.Text;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.UriValidation;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Refuses a tenant declaring a client whose redirect or post-logout redirect URI is not absolute, includes a fragment,
/// or uses a scheme the user agent runs as script: javascript, data or vbscript, and one other than a native app whose
/// redirect URI is not https (RFC 9700 section 2.6).
/// </summary>
/// <remarks>
/// RFC 6749 section 3.1.2: "The redirection endpoint URI MUST be an absolute URI as defined by [RFC3986] Section 4.3",
/// and "The endpoint URI MUST NOT include a fragment component". OpenID Connect RP-Initiated Logout 1.0 calls the
/// post-logout redirect URIs "URLs" without a rule of its own, and they are held to the same two, as dynamic
/// registration holds them, since the user agent is sent to them the same way. A settings value the binder reads as
/// relative may still be a script URI to a browser, whose URL parser removes a tab or a newline anywhere in it and a
/// control character in front of it.
/// <para>
/// A response posted to a script URI runs in this server's origin, whichever kind of client names it. A web client's
/// redirect URIs are held to https besides, since an authorization response rides them, while its post-logout redirect
/// URIs are not; a native app's URIs are <see cref="NativeClientsCheck"/>'s to judge.
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
    /// character other than a space percent-encoded, so the value cannot break or hide inside the logged line, and each
    /// percent sign too, so an encoding the settings spell out is told from one this method adds.
    /// </summary>
    /// <param name="uri">A redirect or post-logout redirect URI, or null for an empty settings value.</param>
    internal static string Shown(Uri? uri)
    {
        var value = uri?.OriginalString ?? string.Empty;
        var shown = new StringBuilder(value.Length);
        foreach (var rune in value.EnumerateRunes())
        {
            if (IsInvisible(rune) || rune.Value == '%')
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
            .Select(redirect => Failure(client, redirect.Member, redirect.Uri))
            .Concat(WebClientFailures(client));

    /// <summary>
    /// The redirect URIs of a web client that are not https, which RFC 9700 section 2.6 forbids ("MUST NOT allow
    /// redirection URIs that use the http scheme except for native clients that use loopback interface redirection")
    /// and RFC 8252 section 7.1 leaves private-use schemes to native apps for. A native app's URIs are
    /// NativeClientsCheck's to judge, and a post-logout redirect carries no authorization response, so it is not held to
    /// the rule.
    /// </summary>
    private static IEnumerable<string> WebClientFailures(ClientInfo client)
    {
        if (client.ApplicationType == ApplicationTypes.Native)
            return [];

        return
            from uri in client.RedirectUris
            where !Refuses(uri) && !RedirectUriSchemes.IsAllowed(uri, native: false)
            select $"The client '{client.ClientId}' has the {nameof(ClientInfo.RedirectUris)} '{Shown(uri)}': a web " +
                   $"client redirects to https (RFC 9700 section 2.6), and only a native app " +
                   $"({nameof(ClientInfo.ApplicationType)} '{ApplicationTypes.Native}') to http on a loopback host " +
                   $"or to a private-use scheme.";
    }

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
