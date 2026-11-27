// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;

/// <summary>
/// A client's metadata document found valid, and the client it was found to describe at each tenant that judged it.
/// </summary>
/// <param name="Content">The document as fetched, read again at each tenant: the authentication method the client is
/// held to, and the grant types that depend on it, are chosen among what that tenant admits.</param>
/// <param name="FreshUntil">When it is to be fetched again.</param>
internal sealed record HeldMetadataDocument(string Content, DateTimeOffset FreshUntil)
{
    /// <summary>
    /// The client found at each tenant, by the tenant's id and generation, so a changed definition judges anew.
    /// </summary>
    public ConcurrentDictionary<(string Id, string Generation), ClientInfo> Clients { get; } = new();

    /// <summary>
    /// The client held for <paramref name="tenant"/> as it is now defined, or null when none is.
    /// </summary>
    public ClientInfo? ClientAt(TenantDefinition tenant)
        => Clients.TryGetValue((tenant.Id, tenant.Generation), out var client) ? client : null;

    /// <summary>
    /// Holds <paramref name="client"/> for <paramref name="tenant"/> as it is now defined, unless another client is
    /// held for it already.
    /// </summary>
    /// <param name="tenant">The tenant the client was judged at.</param>
    /// <param name="client">The client judged.</param>
    /// <param name="held">The client held: <paramref name="client"/>, or the one held before it.</param>
    /// <returns>Whether <paramref name="client"/> is the one held.</returns>
    public bool TryHold(TenantDefinition tenant, ClientInfo client, out ClientInfo held)
    {
        held = Clients.GetOrAdd((tenant.Id, tenant.Generation), client);
        return ReferenceEquals(held, client);
    }
}
