// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;

/// <summary>
/// Defines the contract for a storage system responsible for persisting and retrieving
/// backchannel authentication requests in the context of Client-Initiated Backchannel Authentication (CIBA).
/// </summary>
public interface IBackChannelRequestStorage
{
	/// <summary>
	/// Asynchronously stores a backchannel authentication request in the storage system.
	/// This method saves the provided authentication request and sets its expiration based on the specified duration.
	/// </summary>
	/// <param name="authenticationRequest">The backchannel authentication request to store.</param>
	/// <param name="expiresIn">The duration after which the stored request will expire.</param>
	/// <returns>
	/// A task that returns the ID of the stored authentication request.
	/// </returns>
	Task<string> StoreAsync(BackChannelAuthenticationRequest authenticationRequest, TimeSpan expiresIn);

	/// <summary>
	/// Tries to retrieve a backchannel authentication request by its unique identifier.
	/// This method checks if a request exists for the specified ID and returns it if found.
	/// </summary>
	/// <param name="authenticationRequestId">The unique identifier of the authentication request to retrieve.</param>
	/// <returns>
	/// A task that returns the authentication request if found;
	/// otherwise, null.
	/// </returns>
	Task<BackChannelAuthenticationRequest?> TryGetAsync(string authenticationRequestId);

	/// <summary>
	/// Updates an existing backchannel authentication request in storage.
	/// Used in ping mode to update request status when user completes authentication.
	/// </summary>
	/// <param name="requestId">The unique identifier of the authentication request to update.</param>
	/// <param name="request">The updated authentication request data.</param>
	/// <param name="expiresIn">The duration after which the request expires.</param>
	/// <returns>A task that completes when the request is updated in storage.</returns>
	Task UpdateAsync(
		string requestId,
		BackChannelAuthenticationRequest request,
		TimeSpan expiresIn);

	/// <summary>
	/// Atomically retrieves and removes a backchannel authentication request from storage.
	/// This operation prevents race conditions where multiple concurrent requests could retrieve the same
	/// authentication request before it's removed (poll mode double-retrieval vulnerability).
	/// </summary>
	/// <param name="authenticationRequestId">The unique identifier of the authentication request to remove.</param>
	/// <returns>
	/// A task that returns the authentication request when this caller removed it and still held its own
	/// claim afterwards. Null otherwise, which covers the request not being there, another caller having
	/// taken it, a claim that expired mid-protocol, and the request being gone with nobody able to be told
	/// they took it - the last two without any competitor at all.
	/// </returns>
	Task<BackChannelAuthenticationRequest?> TryRemoveAsync(string authenticationRequestId);
}
