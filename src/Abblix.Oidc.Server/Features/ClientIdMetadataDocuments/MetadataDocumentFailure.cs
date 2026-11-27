// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;

/// <summary>
/// Why a client's metadata document could not be had, and whether that may pass.
/// </summary>
/// <remarks>
/// Section 6.1 of draft-ietf-oauth-client-id-metadata-document "distinguishes two classes of discovery failure": a
/// transient one, "a network error or timeout", after which the server "SHOULD NOT discard previously cached valid
/// client metadata", and a terminal one, where "the document was retrieved but was malformed, or was rejected on trust
/// or validation grounds".
/// </remarks>
/// <param name="MayPass">Whether the failure may pass, so a copy held from an earlier fetch is still served.</param>
/// <param name="Reason">What went wrong, for the log.</param>
internal sealed record MetadataDocumentFailure(bool MayPass, string Reason)
{
    /// <summary>A failure that may pass: the network, a timeout, a server error.</summary>
    public static MetadataDocumentFailure Transient(string reason) => new(true, reason);

    /// <summary>A failure that will not pass by itself: the document was had and refused.</summary>
    public static MetadataDocumentFailure Terminal(string reason) => new(false, reason);
}
