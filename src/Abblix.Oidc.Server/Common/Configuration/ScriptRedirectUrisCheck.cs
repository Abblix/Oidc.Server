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
/// Refuses a tenant declaring a client whose redirect or post-logout redirect URI uses a scheme the user agent runs as
/// script: javascript, data or vbscript.
/// </summary>
/// <remarks>
/// A response posted to such a URI runs in this server's origin, whichever kind of client names it. A web client the
/// host declares is otherwise held to no scheme rule, unlike a native app (<see cref="NativeClientsCheck"/>): the host
/// may send its own web clients wherever it trusts, so only the schemes that turn a redirect into script are refused.
/// </remarks>
internal sealed class ScriptRedirectUrisCheck : ITenantsCheck
{
    private static readonly HashSet<string> ScriptSchemes = new(StringComparer.OrdinalIgnoreCase)
    {
        "javascript",
        "data",
        "vbscript",
    };

    /// <summary>
    /// Whether <paramref name="uri"/> uses a scheme the user agent runs as script, which this check refuses for every
    /// client, so another check of a client's redirect URIs leaves it to this one.
    /// </summary>
    /// <param name="uri">A redirect or post-logout redirect URI.</param>
    internal static bool IsScript(Uri uri) => uri.IsAbsoluteUri && ScriptSchemes.Contains(uri.Scheme);

    /// <inheritdoc />
    public IEnumerable<TenantRefusal> Check(IReadOnlyCollection<TenantDefinition> tenants, OidcOptions options)
        => TenantRefusal.EachOf(tenants, tenant => tenant.Clients.SelectMany(Failures));

    private static IEnumerable<string> Failures(ClientInfo client)
        => client.RedirectUris
            .Select(uri => (Member: nameof(ClientInfo.RedirectUris), Uri: uri))
            .Concat(client.PostLogoutRedirectUris
                .Select(uri => (Member: nameof(ClientInfo.PostLogoutRedirectUris), Uri: uri)))
            .Where(redirect => IsScript(redirect.Uri))
            .Select(redirect =>
                $"The client '{client.ClientId}' has the {redirect.Member} '{redirect.Uri}' of the " +
                $"{redirect.Uri.Scheme} scheme, which runs as script in this server's origin when a response is " +
                $"posted to it.");
}
