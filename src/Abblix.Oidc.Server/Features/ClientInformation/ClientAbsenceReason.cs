// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Why a client identifier does not name a client the server serves.
/// </summary>
public enum ClientAbsenceReason
{
    /// <summary>
    /// No client is known under the identifier.
    /// </summary>
    Unknown,

    /// <summary>
    /// The identifier is a client identifier URL whose metadata document was had and refused: it is invalid, or the
    /// tenant does not accept the client it describes. Produced by client metadata documents as
    /// draft-ietf-oauth-client-id-metadata-document-03 section 6.1 describes a terminal failure, and may change with
    /// the final specification.
    /// </summary>
    [Experimental(ClientIdMetadataDocumentsExperiment.DiagnosticId, UrlFormat = ClientIdMetadataDocumentsExperiment.UrlFormat)]
    Refused,

    /// <summary>
    /// The identifier is a client identifier URL whose metadata document could not be had for a reason that may pass,
    /// such as the network or a server error, and no valid copy of it is held. Produced by client metadata documents as
    /// draft-ietf-oauth-client-id-metadata-document-03 section 6.1 describes a transient failure, and may change with
    /// the final specification.
    /// </summary>
    [Experimental(ClientIdMetadataDocumentsExperiment.DiagnosticId, UrlFormat = ClientIdMetadataDocumentsExperiment.UrlFormat)]
    TemporarilyUnavailable,
}
