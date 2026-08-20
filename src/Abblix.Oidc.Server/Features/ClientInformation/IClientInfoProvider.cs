// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Provides access to OAuth 2.0 client information, enabling the retrieval of client details by client ID.
/// </summary>
/// <remarks>
/// This interface is crucial for supporting OAuth 2.0 and OpenID Connect operations, such as token issuance
/// and validation, by allowing the system to retrieve the configuration and settings for registered clients.
/// It abstracts the underlying storage mechanism, whether it's a database, in-memory collection, or an external service.
/// </remarks>
public interface IClientInfoProvider
{
	/// <summary>
	/// Asynchronously attempts to find a client's information using its unique identifier.
	/// </summary>
	/// <param name="clientId">The unique identifier of the client whose information is being requested.</param>
	/// <returns>
	/// A task that returns the client's information if found;
	/// otherwise, null. This allows for non-blocking queries to the underlying client information storage.
	/// </returns>
	/// <remarks>
	/// This method facilitates dynamic client management by enabling on-demand lookup of client configurations
	/// during OAuth 2.0 and OpenID Connect flows, supporting scenarios such as dynamic client registration
	/// and configuration updates.
	/// </remarks>
	Task<ClientInfo?> TryFindClientAsync(string clientId);
}
