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
/// Represents a registry that manages the statuses of JSON Web Tokens (JWTs). This registry allows for tracking
/// and updating the status of tokens, such as marking them as used or revoked.
/// </summary>
public interface ITokenRegistry
{
	/// <summary>
	/// Asynchronously retrieves the current status of a specified JWT identifier.
	/// </summary>
	/// <param name="jwtId">The identifier of the JWT whose status is to be queried.</param>
	/// <returns>A task that, when completed successfully, returns the <see cref="JsonWebTokenStatus"/>
	/// indicating the current status of the JWT (e.g., active, revoked).</returns>
	Task<JsonWebTokenStatus> GetStatusAsync(string jwtId);

	/// <summary>
	/// Asynchronously sets the status for a specified JWT identifier. This operation may be used to mark a token
	/// as used or revoked.
	/// </summary>
	/// <param name="jwtId">The identifier of the JWT whose status is to be updated.</param>
	/// <param name="status">The new status to be assigned to the JWT, such as <see cref="JsonWebTokenStatus.Used"/> or
	/// <see cref="JsonWebTokenStatus.Revoked"/>.</param>
	/// <param name="expiresAt">The expiration time of the JWT. This is used to determine if the status should be
	/// updated based on the token's validity.</param>
	/// <returns>A task representing the asynchronous operation of updating the token's status.</returns>
	Task SetStatusAsync(string jwtId, JsonWebTokenStatus status, DateTimeOffset expiresAt);
}
