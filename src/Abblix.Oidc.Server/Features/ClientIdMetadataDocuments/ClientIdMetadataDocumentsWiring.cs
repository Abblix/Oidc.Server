// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;

/// <summary>
/// What the container holds that clients resolved from their metadata documents depend on, read at startup so a host
/// missing either does not serve a request.
/// </summary>
/// <remarks>
/// Riding the options-validation pipeline is what buys the timing, as for the consent provider's choice: the host runs
/// startup validators before it opens the port.
/// </remarks>
internal sealed class ClientIdMetadataDocumentsWiring
{
    /// <summary>
    /// What a host is told when the client store it resolves does not look clients up by their documents.
    /// </summary>
    internal const string StoreReplacedMessage =
        "AddClientIdMetadataDocuments() was called, and the discovery document advertises " +
        "client_id_metadata_document_supported, but the IClientInfoProvider the container resolves does not resolve " +
        "clients from their metadata documents: it was registered after AddClientIdMetadataDocuments(), which wraps " +
        "the one registered before it. Register the client store first, or call AddClientIdMetadataDocuments() after it.";

    /// <summary>
    /// What a host is told when its authorization responses carry no issuer.
    /// </summary>
    internal const string IssuerNotSentMessage =
        "AddClientIdMetadataDocuments() was called, but the IAuthorizationMetadataProvider the container resolves " +
        "sends no iss parameter in authorization responses: draft-ietf-oauth-client-id-metadata-document section 7 " +
        "says \"The authorization response MUST include the iss parameter, as defined in [RFC9207]\". Keep " +
        "AuthorizationResponseIssParameterSupported on.";

    /// <summary>
    /// What a host is told when it grants every client everything and accepts a document from any URL.
    /// </summary>
    internal const string ConsentGrantedToAnyUrlMessage =
        "AddClientIdMetadataDocuments() was called with no ClientIdMetadataDocuments.AllowedClientIdPrefixes, and the " +
        "consent provider is the one AddConsentGrantedForEveryClient() registers (NullConsentService), so any URL " +
        "could name itself a client and obtain an end user's tokens without the end user being asked. Set " +
        "AllowedClientIdPrefixes to the URLs of clients you trust, or register an IUserConsentsProvider that asks the " +
        "end user for consent.";

    /// <summary>
    /// What a host is told when it lets the server reach private networks.
    /// </summary>
    internal const string PrivateNetworksReachedMessage =
        "AddClientIdMetadataDocuments() was called while SecureHttpFetchOptions.BlockPrivateNetworks is false, so any " +
        "URL naming itself a client could have the server fetch from a private or special-use address: " +
        "draft-ietf-oauth-client-id-metadata-document section 10.7 says the server \"MUST NOT fetch a Client ID " +
        "Metadata Document URL or any URLs contained within a Client ID Metadata Document that resolve to special-use " +
        "IP addresses\". Keep BlockPrivateNetworks on, and name a service of your own in AllowedDestinations instead.";

    /// <summary>
    /// Whether the client store the container resolves is the one looking clients up by their documents.
    /// </summary>
    public bool StoreResolvesDocuments { get; set; }

    /// <summary>
    /// Whether authorization responses carry the issuer (RFC 9207).
    /// </summary>
    public bool IssuerSent { get; set; }

    /// <summary>
    /// Whether every client is granted everything it asks for while a document is accepted from any URL.
    /// </summary>
    public bool ConsentGrantedToAnyUrl { get; set; }

    /// <summary>
    /// Whether the server's outbound fetches refuse private and special-use addresses.
    /// </summary>
    public bool PrivateNetworksBlocked { get; set; }
}
