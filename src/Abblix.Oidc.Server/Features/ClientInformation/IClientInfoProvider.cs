// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Utils;
namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Provides access to OAuth 2.0 client information, enabling the retrieval of client details by client ID.
/// </summary>
/// <remarks>
/// This interface is crucial for supporting OAuth 2.0 and OpenID Connect operations, such as token issuance
/// and validation, by allowing the system to retrieve the configuration and settings for registered clients.
/// It abstracts the underlying storage mechanism, whether it's a database, in-memory collection, or an external service.
/// <para>
/// A host implements it to supply its clients, and library code resolves it to ask for one.
/// </para>
/// <para>
/// Every lookup names the tenant it is made for, and a client is found only among that tenant's: a client known at
/// one tenant is unknown at another.
/// </para>
/// </remarks>
public interface IClientInfoProvider
{
	/// <summary>
	/// Finds the client <paramref name="clientId"/> names at <paramref name="tenant"/>.
	/// </summary>
	/// <param name="tenant">The tenant whose clients are searched.</param>
	/// <param name="clientId">The identifier of the client.</param>
	/// <returns>
	/// The client, or why the identifier names none. A store answers <see cref="ClientAbsence.Unknown"/> for an
	/// identifier it does not hold; the other reasons belong to clients resolved from their metadata documents.
	/// </returns>
	Task<Result<ClientInfo, ClientAbsence>> FindClientAsync(TenantDefinition tenant, string clientId);
}
