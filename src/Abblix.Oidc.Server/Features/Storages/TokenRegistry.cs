// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.Tokens.Revocation;

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// Manages the registration and tracking of JSON Web Token (JWT) statuses within a persistent storage.
/// This class is responsible for determining the current status of JWTs, such as whether they are active,
/// revoked, or expired, and updating these statuses as necessary.
/// </summary>
/// <param name="storage">The storage mechanism that will handle the persistence of token statuses.</param>
/// <param name="keyFactory">The factory for generating standardized storage keys.</param>
public class TokenRegistry(IEntityStorage storage, IEntityStorageKeyFactory keyFactory) : ITokenRegistry
{
	/// <summary>
	/// Retrieves the current status of a JWT by its identifier.
	/// </summary>
	/// <param name="jwtId">The identifier of the JWT whose status is being queried.</param>
	/// <returns>A task that resolves to the status of the JWT if found; otherwise, a default status indicating
	/// the token does not exist in the registry.</returns>
	public Task<JsonWebTokenStatus> GetStatusAsync(string jwtId)
		=> storage.GetAsync<JsonWebTokenStatus>(keyFactory.JsonWebTokenStatusKey(jwtId), false);

	/// <summary>
	/// Sets or updates the status of a JWT by its identifier, with an expiration on the status entry.
	/// </summary>
	/// <param name="jwtId">The identifier of the JWT whose status is being set.</param>
	/// <param name="status">The status to assign to the JWT.</param>
	/// <param name="expiresAt">The time at which the status record should expire.</param>
	/// <returns>A task representing the asynchronous operation of setting the token's status.</returns>
	public Task SetStatusAsync(string jwtId, JsonWebTokenStatus status, DateTimeOffset expiresAt)
		=> storage.SetAsync(keyFactory.JsonWebTokenStatusKey(jwtId), status, new () { AbsoluteExpiration = expiresAt });
}
