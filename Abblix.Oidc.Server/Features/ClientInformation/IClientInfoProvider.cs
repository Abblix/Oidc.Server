// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
	/// A task that represents the asynchronous operation, resulting in the client's information if found;
	/// otherwise, null. This allows for non-blocking queries to the underlying client information storage.
	/// </returns>
	/// <remarks>
	/// This method facilitates dynamic client management by enabling on-demand lookup of client configurations
	/// during OAuth 2.0 and OpenID Connect flows, supporting scenarios such as dynamic client registration
	/// and configuration updates.
	/// </remarks>
	Task<ClientInfo?> TryFindClientAsync(string clientId);
}
