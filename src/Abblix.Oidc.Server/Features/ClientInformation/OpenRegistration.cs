// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Whether the settings let somebody nobody reviewed become a client: the one answer the trust set on a client when it
/// is created, the startup refusal of consent granted to every client and the grant types and resources a client
/// registering openly is given are all read from.
/// </summary>
internal static class OpenRegistration
{
    /// <summary>
    /// Whether any URL may name itself a client by its metadata document: no
    /// <see cref="ClientIdMetadataDocumentOptions.AllowedClientIdPrefixes"/> names a prefix the URLs fetched start with.
    /// An empty list, refused at startup, counts as none, so nothing is trusted by it.
    /// </summary>
    public static bool AdmitsAnyDocument(OidcOptions options)
        => options.ClientIdMetadataDocuments.AllowedClientIdPrefixes is not { Length: > 0 };

    /// <summary>
    /// Whether anybody may register a client dynamically: registration asks no initial access token, and no software
    /// statement from an issuer the host trusts. A registration made while it is open is
    /// <see cref="ClientTrust.Unreviewed"/>.
    /// </summary>
    public static bool AdmitsAnyRegistrant(OidcOptions options)
        => !options.RequireInitialAccessToken &&
           options.SoftwareStatement is not { RequireSoftwareStatement: true, TrustedIssuers.Length: > 0 };
}
