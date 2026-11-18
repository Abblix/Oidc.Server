// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;

/// <summary>
/// A client's metadata document as read, and the client it was found to describe at each tenant that judged it.
/// </summary>
/// <param name="Metadata">The registration metadata the document describes the client with.</param>
/// <param name="FreshUntil">When it is to be fetched again.</param>
internal sealed record HeldMetadataDocument(ClientRegistrationRequest Metadata, DateTimeOffset FreshUntil)
{
    /// <summary>
    /// The client found at each tenant, by the tenant's id and generation, so a changed definition judges anew.
    /// </summary>
    public ConcurrentDictionary<(string Id, string Generation), ClientInfo> Clients { get; } = new();
}
