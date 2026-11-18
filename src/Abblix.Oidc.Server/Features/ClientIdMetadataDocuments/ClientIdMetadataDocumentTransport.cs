// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;

/// <summary>
/// The HTTP transport a client's metadata document is fetched on, from the URL the client uses as its identifier.
/// </summary>
public static class ClientIdMetadataDocumentTransport
{
    /// <summary>
    /// The name the transport's client is registered under, published so a host can configure it without copying the
    /// string: <c>services.AddHttpClient(ClientIdMetadataDocumentTransport.HttpClientName)</c> reaches the same client
    /// the fetch resolves.
    /// </summary>
    /// <remarks>
    /// Whatever a host chains runs outside the SSRF validation, which is this client's primary handler, so every
    /// retried attempt is validated afresh.
    /// </remarks>
    public const string HttpClientName = "Abblix.Oidc.Server.ClientIdMetadataDocument";
}
