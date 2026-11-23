// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.UriValidation;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Refuses a tenant declaring a native app that RFC 8252, OAuth 2.0 for Native Apps, has an authorization server
/// refuse: one redirecting to a private-use scheme without a period or to http off the loopback host, or one
/// authenticating at the token endpoint with any credential.
/// </summary>
/// <remarks>
/// A native app turning PKCE off is not refused here: the authorization endpoint holds it to PKCE whatever it states
/// (<see cref="ClientInfo.EffectivePkceRequired"/>).
/// </remarks>
internal sealed class NativeClientsCheck : ITenantsCheck
{
    /// <inheritdoc />
    public IEnumerable<TenantRefusal> Check(IReadOnlyCollection<TenantDefinition> tenants, OidcOptions options)
        => TenantRefusal.EachOf(
            tenants,
            tenant => tenant.Clients.Where(client => client.ApplicationType == ApplicationTypes.Native).SelectMany(Failures));

    private static IEnumerable<string> Failures(ClientInfo client)
    {
        var redirects = client.RedirectUris
            .Select(uri => (Member: nameof(ClientInfo.RedirectUris), Uri: uri))
            .Concat(client.PostLogoutRedirectUris
                .Select(uri => (Member: nameof(ClientInfo.PostLogoutRedirectUris), Uri: uri)));

        // RFC 8252 section 8.4: "At a minimum, any private-use URI scheme that doesn't contain a period character (".")
        // SHOULD be rejected", and section 7.3 has loopback redirects use the http scheme. A URI that is not absolute,
        // includes a fragment or uses a script scheme is RedirectUrisCheck's to refuse, for every client
        foreach (var (member, uri) in redirects)
        {
            if (!RedirectUrisCheck.Refuses(uri) && !RedirectUriSchemes.IsAllowed(uri, native: true))
            {
                yield return $"The native client '{client.ClientId}' has the {member} " +
                             $"'{RedirectUrisCheck.Shown(uri)}': a native app redirects to a private-use scheme " +
                             $"based on a domain name in reverse order, such as " +
                             $"com.example.app (RFC 8252 section 7.1), to https, or to http on a loopback host.";
            }
        }

        foreach (var responseType in client.EffectiveResponseTypes.Where(responseType => !responseType.ServesNativeApps()))
        {
            yield return $"The native client '{client.ClientId}' is allowed the response type " +
                         $"'{string.Join(' ', responseType)}', which carries no code: PKCE cannot protect it, so a " +
                         $"native app uses one carrying a code (RFC 8252 section 8.2, RFC 9700 section 2.1.2).";
        }

        // RFC 8252 section 8.4 has native apps "classified as public clients" except "when using a mechanism like
        // Dynamic Client Registration to provision per-instance secrets", and Appendix A item 4 has a server "Not
        // assume that native app clients can keep a secret". A native app declared once in the tenant settings is one
        // registration serving every installation, so it is a public client; credentials of its own installation reach
        // the server through dynamic registration or the host's client registration store
        if (client.ClientType != ClientType.Public)
        {
            yield return $"The native client '{client.ClientId}' authenticates with " +
                         $"'{client.TokenEndpointAuthMethod}': a native app declared once in the tenant settings " +
                         $"serves every installation and is a public client (RFC 8252 section 8.4), so set " +
                         $"{nameof(ClientInfo.TokenEndpointAuthMethod)} to '{ClientAuthenticationMethods.None}'; " +
                         $"credentials of each installation go through dynamic registration or the host's " +
                         $"{nameof(ITenantClientRegistrationStore)}.";
        }
    }
}
