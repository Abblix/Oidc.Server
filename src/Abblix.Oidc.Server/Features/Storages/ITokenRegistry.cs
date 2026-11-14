// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;
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
	/// <param name="tenant">The tenant the token belongs to.</param>
	/// <param name="jwtId">The identifier of the JWT whose status is to be queried.</param>
	/// <returns>A task that returns the <see cref="JsonWebTokenStatus"/> of the JWT
	/// (e.g., active, revoked).</returns>
	Task<JsonWebTokenStatus> GetStatusAsync(TenantDefinition tenant, string jwtId);

	/// <summary>
	/// Asynchronously sets the status for a specified JWT identifier. This operation may be used to mark a token
	/// as used or revoked.
	/// </summary>
	/// <param name="tenant">The tenant the token belongs to.</param>
	/// <param name="jwtId">The identifier of the JWT whose status is to be updated.</param>
	/// <param name="status">The new status to be assigned to the JWT, such as <see cref="JsonWebTokenStatus.Used"/> or
	/// <see cref="JsonWebTokenStatus.Revoked"/>.</param>
	/// <param name="expiresAt">The expiration time of the JWT. This is used to determine if the status should be
	/// updated based on the token's validity.</param>
	/// <returns>A task representing the asynchronous operation of updating the token's status.</returns>
	Task SetStatusAsync(TenantDefinition tenant, string jwtId, JsonWebTokenStatus status, DateTimeOffset expiresAt);

	/// <summary>
	/// Records <paramref name="status"/> for a JWT only when nothing is recorded for it yet, and reports whether
	/// this caller is the one that recorded it.
	/// </summary>
	/// <remarks>
	/// Of several callers racing for one token, at most one is told it recorded the status, within the reach
	/// <see cref="IEntityStorage.TrySetIfAbsentAsync{T}"/> gives the registered storage: one process for the
	/// built-in storage over a distributed cache, every node for a storage whose backing store decides the write
	/// itself. A host implementing this interface makes the check and the write one step, because a check followed
	/// by a separate write lets two requests presenting a single-use token together both find it unspent.
	/// </remarks>
	/// <param name="tenant">The tenant the token belongs to.</param>
	/// <param name="jwtId">The identifier of the JWT whose status is to be recorded.</param>
	/// <param name="status">The status to record.</param>
	/// <param name="expiresAt">When the record may be dropped.</param>
	/// <returns>True when nothing was recorded and this caller recorded <paramref name="status"/>; false when a
	/// status was already recorded.</returns>
	Task<bool> TrySetStatusAsync(TenantDefinition tenant, string jwtId, JsonWebTokenStatus status, DateTimeOffset expiresAt);
}
