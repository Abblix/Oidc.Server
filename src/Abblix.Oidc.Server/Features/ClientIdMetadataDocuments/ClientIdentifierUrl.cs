// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;

/// <summary>
/// What a client identifier must be for the server to fetch the metadata document behind it: a Client Identifier URL
/// of draft-ietf-oauth-client-id-metadata-document section 3, read as the string the client sent.
/// </summary>
/// <remarks>
/// Section 3 has the server compare these URLs "using simple string comparison" and says it "MUST NOT normalize Client
/// Identifier URLs when performing comparison", so nothing here reads the identifier through <see cref="Uri"/> and
/// back: that would collapse dot segments, drop a default port and lowercase the host, and so judge a different URL
/// from the one the client named.
/// </remarks>
internal static class ClientIdentifierUrl
{
    private static readonly string HttpsPrefix = Uri.UriSchemeHttps + Uri.SchemeDelimiter;
    private const string EncodedSlash = "%2F";
    private const string EncodedBackslash = "%5C";
    private const string DoubleDot = "..";

    /// <summary>
    /// Why <paramref name="clientId"/> is not a Client Identifier URL this server fetches, or null when it is one.
    /// </summary>
    /// <param name="clientId">The client identifier as the request carries it.</param>
    /// <param name="rule">The rule the document is fetched by, which judges an address the URL names as written
    /// (<see cref="SpecialPurposeFetches.DocumentRuleAt"/>).</param>
    /// <param name="url">The URL the document is fetched from, which is <paramref name="clientId"/> itself.</param>
    public static string? WhyNotFetched(string clientId, OutboundAddressRule rule, out Uri? url)
    {
        url = null;

        // Section 3: "MUST use the https URL scheme". Compared as written, since the scheme is part of the string the
        // document's client_id must equal
        if (!clientId.StartsWith(HttpsPrefix, StringComparison.Ordinal))
            return "it does not use the https scheme";

        // Section 3: "MUST NOT contain a fragment component"
        if (clientId.Contains('#'))
            return "it carries a fragment";

        // Section 3 says only that the URL "SHOULD NOT contain a query component". Refusing one is this server's
        // choice: section 4.5 names "input embedded in path or query components" as what must not shape a document,
        // and a query is where a document varying per request is built from
        if (clientId.Contains('?'))
            return "it carries a query";

        if (WhyAuthorityOrPathRefused(clientId) is { } refusal)
            return refusal;

        // Section 3 has the URL carry no "single-dot or double-dot path components", and the document is fetched from
        // the identifier itself (section 4: the client_id "MUST also match the URL that the authorization server used
        // to fetch the document"). So a URL the request would reach in another spelling - a dot segment collapsed,
        // %7E for ~, a default port dropped, an uppercase host - is refused rather than fetched under a name the
        // document cannot match: section 3 leaves that normalization to the client
        if (!Uri.TryCreate(clientId, UriKind.Absolute, out var parsed) ||
            !string.Equals(parsed.AbsoluteUri, clientId, StringComparison.Ordinal))
        {
            return "it is not written in the form it is requested in";
        }

        // Section 10.7 holds the URL to the special-purpose address registries as written, the NAT64 prefix included
        // whatever IPv4 address it carries, loopback aside where its exception applies; a name is judged when it is
        // resolved, by the transport's own validation
        if (IPAddress.TryParse(parsed.Host, out var literal) && rule.Refuses(literal))
            return "it names a special-purpose address";

        url = parsed;
        return null;
    }

    /// <summary>
    /// Whether <paramref name="clientId"/> is withheld from dynamic registration as a URL a metadata document may name:
    /// every client identifier this server fetches, and every https URL in any other spelling.
    /// </summary>
    /// <remarks>
    /// Section 9.1 has a server issuing client identifiers of its own beside documents "ensure that the client_id
    /// strings it generates do not start with https://". A spelling the server never fetches is withheld as well -
    /// the scheme in capitals, white space around it - so no registration holds an id that reads as a document's URL
    /// to whoever compares it less strictly than section 3 does.
    /// </remarks>
    /// <param name="clientId">The client identifier a registration proposes.</param>
    public static bool IsWithheldFromRegistration(string clientId)
        => clientId.StartsWith(HttpsPrefix, StringComparison.Ordinal) ||
           (Uri.TryCreate(clientId, UriKind.Absolute, out var parsed) && parsed.Scheme == Uri.UriSchemeHttps);

    /// <summary>
    /// Why the server does not send a request to <paramref name="url"/>, a Client Identifier URL about to be fetched,
    /// or null when it does: the refusals made before the request, so a URL refused on them is refused on trust grounds
    /// rather than as a network failure.
    /// </summary>
    /// <param name="url">The URL the document is fetched from.</param>
    /// <param name="validator">The synchronous SSRF rules.</param>
    /// <param name="allowedDestinations">The host's <see cref="SecureHttpFetchOptions.AllowedDestinations"/>.</param>
    public static string? WhyNotReached(Uri url, ISecureUriValidator validator, Uri[]? allowedDestinations)
    {
        // Section 10.7: the server "MUST NOT fetch a Client ID Metadata Document URL ... that resolve[s] to special-use
        // IP addresses". The handler judges the address the name resolves to again before the request is sent. A
        // loopback host the scope lets this fetch reach, by the same section's exception, is judged there alone
        if (!SpecialPurposeFetches.PermitsLoopbackHost(url) && validator.Validate(url) is { } rejection)
            return $"the URL is not one this server may reach: {rejection}";

        // A destination the host named reaches past those rules for its own services, chosen by the host or by a
        // registered client; a client identifier is chosen by whoever sends a request, so it is never one of them
        if (SecureUriValidator.IsAllowedDestination(url, allowedDestinations))
            return "the URL is one the host allows for its own services";

        return null;
    }

    private static string? WhyAuthorityOrPathRefused(string clientId)
    {
        var authorityEnd = clientId.IndexOf('/', HttpsPrefix.Length);
        var authority = authorityEnd < 0
            ? clientId[HttpsPrefix.Length..]
            : clientId[HttpsPrefix.Length..authorityEnd];

        // Section 3: "MUST NOT contain a userinfo component"
        if (authority.Contains('@'))
            return "it carries user information";

        // Section 3: "MUST contain a path component other than /"
        if (authorityEnd < 0 || clientId.Length == authorityEnd + 1)
            return "its path is empty or /";

        // A slash or backslash in encoded form, or a segment starting with two dots, is read by some servers as a step
        // out of the path: past an allow-list's prefix, to a document the prefix does not name
        return MayStepOut(clientId[authorityEnd..]) ? "its path may step out of itself" : null;
    }

    private static bool MayStepOut(string path)
        => path.Contains(EncodedSlash, StringComparison.OrdinalIgnoreCase) ||
           path.Contains(EncodedBackslash, StringComparison.OrdinalIgnoreCase) ||
           path.Split('/').Any(segment => segment.StartsWith(DoubleDot, StringComparison.Ordinal));

    /// <summary>
    /// Whether <paramref name="clientId"/> starts with one of <paramref name="allowedPrefixes"/>, or no list is set.
    /// </summary>
    /// <param name="clientId">The client identifier, already found to be a Client Identifier URL.</param>
    /// <param name="allowedPrefixes">The host's list, <see cref="ClientIdMetadataDocumentOptions.AllowedClientIdPrefixes"/>.
    /// </param>
    public static bool IsAllowed(string clientId, string[]? allowedPrefixes)
        => allowedPrefixes is null ||
           allowedPrefixes.Any(prefix => clientId.StartsWith(prefix, StringComparison.Ordinal));
}
