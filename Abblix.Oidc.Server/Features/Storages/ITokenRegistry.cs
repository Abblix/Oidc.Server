// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
// 
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
// 
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
// 
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
// 
// For full licensing terms, please visit:
// 
// https://oidc.abblix.com/license
// 
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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
	/// <returns>A task that returns the <see cref="JsonWebTokenStatus"/> of the JWT
	/// (e.g., active, revoked).</returns>
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
