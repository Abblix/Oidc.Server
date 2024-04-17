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

using Abblix.Oidc.Server.Features.Tokens.Revocation;

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// Manages the registration and tracking of JSON Web Token (JWT) statuses within a persistent storage.
/// This class is responsible for determining the current status of JWTs, such as whether they are active,
/// revoked, or expired, and updating these statuses as necessary.
/// </summary>
public class TokenRegistry : ITokenRegistry
{
	/// <summary>
	/// Initializes a new instance of the <see cref="TokenRegistry"/> class.
	/// </summary>
	/// <param name="storage">The storage mechanism that will handle the persistence of token statuses.</param>
	public TokenRegistry(IEntityStorage storage)
	{
		_storage = storage;
	}

	private readonly IEntityStorage _storage;


	/// <summary>
	/// Retrieves the current status of a JWT by its identifier.
	/// </summary>
	/// <param name="jwtId">The identifier of the JWT whose status is being queried.</param>
	/// <returns>A task that resolves to the status of the JWT if found; otherwise, a default status indicating
	/// the token does not exist in the registry.</returns>
	public Task<JsonWebTokenStatus> GetStatusAsync(string jwtId)
		=> _storage.GetAsync<JsonWebTokenStatus>(jwtId, false);

	/// <summary>
	/// Sets or updates the status of a JWT by its identifier, with an expiration on the status entry.
	/// </summary>
	/// <param name="jwtId">The identifier of the JWT whose status is being set.</param>
	/// <param name="status">The status to assign to the JWT.</param>
	/// <param name="expiresAt">The time at which the status record should expire.</param>
	/// <returns>A task representing the asynchronous operation of setting the token's status.</returns>
	public Task SetStatusAsync(string jwtId, JsonWebTokenStatus status, DateTimeOffset expiresAt)
		=> _storage.SetAsync(jwtId, status, new StorageOptions { AbsoluteExpiration = expiresAt });
}
