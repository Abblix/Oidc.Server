// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Consents;

/// <summary>
/// Whether every client is granted everything it asks for while somebody nobody reviewed may become a client, by
/// either way the server lets one in, which the server refuses at startup: the consent screen is the end user's only
/// check on such a client (RFC 9700 section 4.11.2).
/// </summary>
internal sealed class ConsentForUnreviewedClients
{
    /// <summary>
    /// What a host is told when it grants every client everything and accepts a document from any URL.
    /// </summary>
    internal const string AnyUrlMessage =
        "AddClientIdMetadataDocuments() was called with no ClientIdMetadataDocuments.AllowedClientIdPrefixes, and the " +
        "consent provider is the one AddConsentGrantedForEveryClient() registers (NullConsentService), so any URL " +
        "could name itself a client and obtain an end user's tokens without the end user being asked. Set " +
        "AllowedClientIdPrefixes to the URLs of clients you trust, or register an IUserConsentsProvider that asks the " +
        "end user for consent.";

    /// <summary>
    /// What a host is told when it grants every client everything and lets anybody register one.
    /// </summary>
    internal const string AnyRegistrantMessage =
        "AddDynamicClientRegistration() was called with RequireInitialAccessToken set to false, and the consent " +
        "provider is the one AddConsentGrantedForEveryClient() registers (NullConsentService), so anybody could " +
        "register a client and obtain an end user's tokens without the end user being asked. Keep " +
        "RequireInitialAccessToken on, or register an IUserConsentsProvider that asks the end user for consent.";

    /// <summary>
    /// Whether every client is granted everything while a metadata document is accepted from any URL.
    /// </summary>
    public bool GrantedToAnyUrl { get; set; }

    /// <summary>
    /// Whether every client is granted everything while anybody may register a client.
    /// </summary>
    public bool GrantedToAnyRegistrant { get; set; }
}
