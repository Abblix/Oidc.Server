// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.UriValidation;
using Abblix.Oidc.Server.Model;
using Parameters = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;

namespace Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;

/// <summary>
/// The URI schemes a client's metadata document may use, for the URIs it names.
/// </summary>
/// <remarks>
/// Draft-ietf-oauth-client-id-metadata-document section 10.7: "Authorization servers SHOULD ensure they only fetch or
/// parse URLs with known and supported URI schemes. This can help avoid leading to compromises if a client uses a URI
/// scheme such as javascript: in a metadata property." A document is anybody's, so a redirect URI of the javascript
/// scheme would run the author's script in this server's origin the moment a response is posted to it. So a URI the
/// user agent is sent to uses https, http to a loopback host (RFC 9700 section 2.6 allows the http scheme only "for
/// native clients that use loopback interface redirection"), or a private-use scheme, which RFC 8252 section 7.1 has
/// a native app base "on a domain name under their control, expressed in reverse order" and so carries a period.
/// Every other URI, fetched by the server or shown to the user, uses https.
/// </remarks>
internal static class UriSchemes
{
    /// <summary>
    /// Why a URI <paramref name="metadata"/> names uses a scheme a document may not, or null when none does.
    /// </summary>
    public static string? WhyRefused(ClientRegistrationRequest metadata)
    {
        var redirects = (metadata.RedirectUris ?? []).Select(uri => (Parameters.RedirectUris, uri))
            .Concat(metadata.PostLogoutRedirectUris.Select(uri => (Parameters.PostLogoutRedirectUris, uri)));

        foreach (var (member, uri) in redirects)
        {
            if (uri is not { IsAbsoluteUri: true } || !IsRedirectScheme(uri))
                return $"its {member} holds a URI of a scheme it may not use";
        }

        (string Member, Uri? Uri)[] secured =
        [
            (Parameters.JwksUri, metadata.JwksUri),
            (Parameters.SectorIdentifierUri, metadata.SectorIdentifierUri),
            (Parameters.LogoUri, metadata.LogoUri),
            (Parameters.ClientUri, metadata.ClientUri),
            (Parameters.PolicyUri, metadata.PolicyUri),
            (Parameters.TosUri, metadata.TermsOfServiceUri),
            (Parameters.InitiateLoginUri, metadata.InitiateLoginUri),
            (Parameters.BackChannelLogoutUri, metadata.BackChannelLogoutUri),
            (Parameters.FrontChannelLogoutUri, metadata.FrontChannelLogoutUri),
            (Parameters.BackChannelClientNotificationEndpoint, metadata.BackChannelClientNotificationEndpoint),
            ..(metadata.RequestUris ?? []).Select(uri => (Parameters.RequestUris, (Uri?)uri)),
        ];

        foreach (var (member, uri) in secured)
        {
            if (uri is not null && !(uri.IsAbsoluteUri && uri.Scheme == Uri.UriSchemeHttps))
                return $"its {member} is not an https URI";
        }

        return null;
    }

    private static bool IsRedirectScheme(Uri uri)
    {
        if (uri.Scheme == Uri.UriSchemeHttps)
            return true;

        if (uri.Scheme == Uri.UriSchemeHttp)
            return LoopbackHosts.IsNativeLoopbackHost(uri);

        return uri.Scheme.Contains('.');
    }
}
