// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// How the server treats a client that identifies itself by the URL of its own metadata document instead of a
/// registration (draft-ietf-oauth-client-id-metadata-document): which such URLs it accepts, how much of a document it
/// reads and how long it holds one.
/// </summary>
/// <remarks>
/// None of this applies until the host calls <c>AddClientIdMetadataDocuments()</c>. A client resolved from its
/// document is held to <see cref="OidcOptions.NewClientOptions"/> as a dynamically registered one is, its default
/// scope, the resources and token exchange audiences it may name and the audiences of its assertions among them,
/// because its metadata is as much the client's own word as a registration request is.
/// </remarks>
public record ClientIdMetadataDocumentOptions
{
    /// <summary>
    /// Whether the server resolves clients from their metadata documents and advertises
    /// <c>client_id_metadata_document_supported</c> in its discovery document.
    /// </summary>
    /// <remarks>
    /// Set by <c>AddClientIdMetadataDocuments()</c> alone, never from configuration: the setter is not public, so a
    /// configuration file cannot advertise the feature in discovery while nothing resolves such a client.
    /// </remarks>
    public bool Enabled { get; internal set; }

    /// <summary>
    /// The prefixes a client identifier URL must start with to be fetched, or null (the default) to fetch any URL the
    /// draft's rules allow.
    /// </summary>
    /// <remarks>
    /// Section 10.8 of the draft lets an authorization server "maintain allowlists of trusted domain patterns". Each
    /// entry is an absolute <c>https</c> URL whose path ends with a slash, such as <c>https://apps.example.com/</c>
    /// or <c>https://example.com/clients/</c>, and a client identifier is compared with it character for character:
    /// section 3 has the server compare these URLs "using simple string comparison" and never normalize them, so
    /// <c>https://example.com:443/</c> and <c>https://Example.com/</c> admit nothing that <c>https://example.com/</c>
    /// would. The closing slash is what keeps <c>https://example.com/</c> from admitting
    /// <c>https://example.com.attacker.test/</c>; an entry without one, an empty list, an entry with a query, a
    /// fragment or user information, and one of any other scheme are refused at startup.
    /// </remarks>
    public string[]? AllowedClientIdPrefixes { get; set; }

    /// <summary>
    /// The most of a metadata document the server reads, in bytes; a longer one is refused. Default: 5 KB.
    /// </summary>
    /// <remarks>
    /// Section 10.11 of the draft: authorization servers "SHOULD limit the amount of data they read and process when
    /// fetching a Client ID Metadata Document", and "the recommended maximum size to read is 5 kilobytes".
    /// </remarks>
    public int MaxDocumentSize { get; set; } = 5 * 1024;

    /// <summary>
    /// How long a document is held when its response states no lifetime of its own. Default: 5 minutes.
    /// </summary>
    /// <remarks>
    /// Section 6.2 of the draft: the server "SHOULD respect HTTP cache headers [RFC9111]" and "SHOULD also enforce a
    /// minimum effective cache duration when none is otherwise indicated". So a response carrying <c>max-age</c> is
    /// held for that long, one carrying <c>no-store</c> or <c>no-cache</c> is not held at all, and this applies only
    /// to a response saying nothing about it.
    /// </remarks>
    public TimeSpan MinimumCacheDuration { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// The longest a document is held, whatever its response asks for. Default: 1 hour.
    /// </summary>
    /// <remarks>
    /// Section 6.2 of the draft: the server "SHOULD enforce a maximum effective cache duration regardless of the cache
    /// directives in the response". This bounds how long a redirect URI or a key a client has removed from its
    /// document is still honored here. A document whose lifetime has passed is fetched again on the next request, and
    /// when that fetch fails for a reason that may pass, a network error, a timeout or a 5xx answer, the copy held is
    /// served until this much time has passed since it was fetched: section 6.1 has the server not "discard previously
    /// cached valid client metadata on transient failures".
    /// </remarks>
    public TimeSpan MaximumCacheDuration { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// The most documents held at once. Default: 10000. Read once, when the server starts.
    /// </summary>
    /// <remarks>
    /// Whoever sends an authorization request names the URL, so without a bound a host answering every path with a
    /// document naming that path would fill the server's memory for <see cref="MaximumCacheDuration"/>. A document
    /// arriving while the server holds this many is served to the request that fetched it and not held, so it is fetched
    /// again on its next use, which section 6.2 of the draft allows a server doing "to avoid repeatedly fetching" no
    /// less than it allows holding.
    /// </remarks>
    public int MaxHeldDocuments { get; set; } = 10_000;
}
