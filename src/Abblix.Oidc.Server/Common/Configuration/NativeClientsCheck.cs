// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Refuses a tenant declaring a client that RFC 8252, OAuth 2.0 for Native Apps, has an authorization server refuse:
/// a redirect URI of a script scheme for any client, and for a native app a redirect URI of a private-use scheme without
/// a period, PKCE turned off, or a shared secret as its proof of identity.
/// </summary>
/// <remarks>
/// Dynamic registration holds a client registering itself to the same redirect rule, so a client the host declares is
/// held to it too. A native app's https redirect URI is accepted here: section 7.2 offers native apps the claimed https
/// redirect, which only the registration rule of OpenID Connect Dynamic Client Registration 1.0 section 2 refuses.
/// </remarks>
public sealed class NativeClientsCheck : ITenantsCheck
{
    /// <summary>
    /// Schemes whose URI the user agent runs as content of the page that navigates to it, so a response posted to one
    /// would run in this server's origin.
    /// </summary>
    private static readonly HashSet<string> ScriptSchemes = new(StringComparer.OrdinalIgnoreCase)
    {
        "javascript",
        "data",
        "vbscript",
    };

    /// <inheritdoc />
    public IEnumerable<TenantRefusal> Check(IReadOnlyCollection<TenantDefinition> tenants, OidcOptions options)
        => TenantRefusal.EachOf(tenants, tenant => tenant.Clients.SelectMany(Failures));

    private static IEnumerable<string> Failures(ClientInfo client)
    {
        var native = client.ApplicationType == ApplicationTypes.Native;
        var redirects = client.RedirectUris
            .Select(uri => (Member: nameof(ClientInfo.RedirectUris), Uri: uri))
            .Concat(client.PostLogoutRedirectUris
                .Select(uri => (Member: nameof(ClientInfo.PostLogoutRedirectUris), Uri: uri)));

        foreach (var (member, uri) in redirects)
        {
            if (!uri.IsAbsoluteUri)
                continue;

            if (ScriptSchemes.Contains(uri.Scheme))
            {
                yield return $"The client '{client.ClientId}' has the {member} '{uri}' of the {uri.Scheme} scheme, " +
                             $"which runs as script in this server's origin when a response is posted to it.";
            }
            else if (native && !UriSchemes.IsRedirectScheme(uri))
            {
                // RFC 8252 section 8.4: "At a minimum, any private-use URI scheme that doesn't contain a period
                // character (".") SHOULD be rejected", and section 7.3 has loopback redirects use the http scheme
                yield return $"The native client '{client.ClientId}' has the {member} '{uri}': a native app " +
                             $"redirects to a private-use scheme based on a domain name in reverse order, such as " +
                             $"com.example.app (RFC 8252 section 7.1), to https, or to http on a loopback host.";
            }
        }

        if (!native)
            yield break;

        // RFC 8252 section 8.1: "Authorization servers SHOULD reject authorization requests from native apps that
        // don't use PKCE"
        if (client.PkceRequired is false)
        {
            yield return $"The native client '{client.ClientId}' has {nameof(ClientInfo.PkceRequired)} false: a " +
                         $"native app uses PKCE (RFC 8252 section 8.1).";
        }

        // RFC 8252 section 8.5: an authorization server requiring "a statically included shared secret for native app
        // clients MUST treat the client as a public client ... and not accept the secret as proof of the client's
        // identity". A client the host declares is one registration shared by every installation of the app, so its
        // secret is statically included in each copy
        if (client.TokenEndpointAuthMethod is ClientAuthenticationMethods.ClientSecretBasic
            or ClientAuthenticationMethods.ClientSecretPost
            or ClientAuthenticationMethods.ClientSecretJwt)
        {
            yield return $"The native client '{client.ClientId}' authenticates with " +
                         $"'{client.TokenEndpointAuthMethod}': a secret shipped inside an app proves nothing about " +
                         $"the client (RFC 8252 section 8.5), so set {nameof(ClientInfo.TokenEndpointAuthMethod)} " +
                         $"to '{ClientAuthenticationMethods.None}'.";
        }
    }
}
