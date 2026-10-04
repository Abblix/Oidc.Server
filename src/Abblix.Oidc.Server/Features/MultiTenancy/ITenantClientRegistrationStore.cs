// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Keeps the clients dynamic client registration adds (RFC 7591) under multi-tenancy, for a host that keeps them
/// itself, each with the identifier of the registration access token that manages it (RFC 7592).
/// </summary>
/// <remarks>
/// Every call names the tenant of the request, and a registration is kept and found under that tenant's
/// <see cref="TenantDefinition.Id"/> and <see cref="TenantDefinition.Generation"/> together: a registration made at
/// one tenant is never found at another, and a tenant created again under an id finds none of the registrations made
/// at the creation before it. Client ids are compared without regard to case, as the server compares them.
/// <para>
/// The clients a tenant's definition configures stay in the definition, and the server keeps them apart from what
/// this store holds: a configured client is served over a registration under its id, a registration the server meets
/// under such an id - found, added or changed - is removed and answered as not found or not made, and one no request
/// meets stays in this store until the host deletes it.
/// </para>
/// <para>
/// An addition takes effect only where no registration is held under the client's id; a change or a removal only
/// while the registration held there carries the token identifier of the one it was decided on. Each answers
/// whether it took effect. Registered as a singleton, as the server's client store that calls it is: that store
/// would hold one registered for a request for every request after the first, and a container validating its scopes
/// refuses it at startup.
/// </para>
/// <para>
/// The registrations of a creation of a tenant the host removes are the host's to delete: the server only stops
/// asking for them. A host learning of the release from the server registers on
/// <see cref="StoreTenantCatalog.Released"/> for each tenant an <see cref="ITenantOpening"/> of its own readies.
/// </para>
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public interface ITenantClientRegistrationStore
{
    /// <summary>
    /// Finds the registration held at <paramref name="tenant"/> under <paramref name="clientId"/>.
    /// </summary>
    /// <param name="tenant">The tenant of the request.</param>
    /// <param name="clientId">The client id to look up.</param>
    /// <returns>The registration, or null when none is held there.</returns>
    Task<RegisteredClient?> TryFindAsync(TenantDefinition tenant, string clientId);

    /// <summary>
    /// Adds <paramref name="client"/> at <paramref name="tenant"/>, unless a registration is held there under its id.
    /// </summary>
    /// <param name="tenant">The tenant of the request.</param>
    /// <param name="client">The client and the identifier of the registration access token issued for it.</param>
    /// <returns>Whether the registration was added.</returns>
    Task<bool> TryAddAsync(TenantDefinition tenant, RegisteredClient client);

    /// <summary>
    /// Replaces the registration held at <paramref name="tenant"/> under the client's id with
    /// <paramref name="updated"/>, while it carries the token identifier of <paramref name="current"/>.
    /// </summary>
    /// <param name="tenant">The tenant of the request.</param>
    /// <param name="current">The registration the change was decided on.</param>
    /// <param name="updated">The registration replacing it.</param>
    /// <returns>Whether the registration was replaced.</returns>
    Task<bool> TryReplaceAsync(TenantDefinition tenant, RegisteredClient current, RegisteredClient updated);

    /// <summary>
    /// Removes the registration held at <paramref name="tenant"/> under the client's id, while it carries the token
    /// identifier of <paramref name="current"/>.
    /// </summary>
    /// <param name="tenant">The tenant of the request.</param>
    /// <param name="current">The registration the removal was decided on.</param>
    /// <returns>Whether the registration was removed.</returns>
    Task<bool> TryRemoveAsync(TenantDefinition tenant, RegisteredClient current);
}
