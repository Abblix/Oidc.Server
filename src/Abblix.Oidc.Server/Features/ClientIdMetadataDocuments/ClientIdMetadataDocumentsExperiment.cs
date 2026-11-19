// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;

/// <summary>
/// The diagnostic a host meets when it uses Client ID Metadata Documents, which implement an Internet-Draft
/// (draft-ietf-oauth-client-id-metadata-document-03) and may change in a minor release until it becomes an RFC.
/// </summary>
/// <remarks>
/// A thousand of its own, so it never meets the analyzer rules of this repository (ABX1xxx) or of the shared
/// libraries (ABX2xxx).
/// </remarks>
internal static class ClientIdMetadataDocumentsExperiment
{
    /// <summary>The diagnostic id a host suppresses to use the feature.</summary>
    public const string DiagnosticId = "ABX9001";

    /// <summary>Where the diagnostic points: the feature's section of the package README.</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Minor Code Smell", "S1075",
        Justification = "The address is the published documentation of the feature, which a host follows from its build.")]
    public const string UrlFormat =
        "https://github.com/Abblix/Oidc.Server/blob/master/src/Abblix.Oidc.Server/README.md#client-id-metadata-documents";
}
