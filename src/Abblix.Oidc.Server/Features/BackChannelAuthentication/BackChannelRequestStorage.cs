// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.Storages;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication;

/// <summary>
/// Implements the storage of backchannel authentication requests, allowing for persistence
/// and retrieval of authentication request data in the context of Client-Initiated Backchannel Authentication (CIBA).
/// </summary>
/// <param name="storage">The storage system used for persisting authentication requests.</param>
/// <param name="authenticationRequestIdGenerator">Generator for creating unique authentication request IDs.</param>
/// <param name="keyFactory">The factory for generating standardized storage keys.</param>
public class BackChannelRequestStorage(
	IEntityStorage storage,
	IAuthenticationRequestIdGenerator authenticationRequestIdGenerator,
	IEntityStorageKeyFactory keyFactory) : IBackChannelRequestStorage
{
	/// <summary>
	/// Asynchronously stores a backchannel authentication request and generates a unique identifier for it.
	/// This method also sets an expiration duration for the stored request.
	/// </summary>
	/// <param name="authenticationRequest">The backchannel authentication request to store.</param>
	/// <param name="expiresIn">The duration after which the stored request will expire.</param>
	/// <returns>
	/// A task that returns the unique ID of the stored authentication request.
	/// </returns>
	public async Task<string> StoreAsync(BackChannelAuthenticationRequest authenticationRequest, TimeSpan expiresIn)
	{
		var authenticationRequestId = authenticationRequestIdGenerator.GenerateAuthenticationRequestId();

		await storage.SetAsync(
			keyFactory.BackChannelAuthenticationRequestKey(authenticationRequestId),
			authenticationRequest,
			new() { AbsoluteExpirationRelativeToNow = expiresIn });

		return authenticationRequestId;
	}

	/// <summary>
	/// Tries to retrieve a backchannel authentication request by its unique identifier.
	/// </summary>
	/// <param name="authenticationRequestId">The unique identifier of the authentication request to retrieve.</param>
	/// <returns>
	/// A task that returns the authentication request if found;
	/// otherwise, null.
	/// </returns>
	public Task<BackChannelAuthenticationRequest?> TryGetAsync(string authenticationRequestId)
	{
		// A status read must NOT consume the request. The CIBA grant handler calls this on every poll/ping
		// to inspect the status and only redeems once, via TryRemoveAsync, on successful token issuance.
		// Consuming here made every successful poll/ping fail with invalid_grant and let a slow_down poll or
		// a wrong-client lookup destroy a still-pending authentication.
		return storage.GetAsync<BackChannelAuthenticationRequest>(
			keyFactory.BackChannelAuthenticationRequestKey(authenticationRequestId),
			removeOnRetrieval: false);
	}

	/// <summary>
	/// Updates an existing backchannel authentication request in storage.
	/// Used in ping mode to update request status when user completes authentication.
	/// </summary>
	/// <param name="requestId">The unique identifier of the authentication request to update.</param>
	/// <param name="request">The updated authentication request data.</param>
	/// <param name="expiresIn">The duration after which the request expires.</param>
	/// <returns>A task that completes when the request is updated in storage.</returns>
	public Task UpdateAsync(
		string requestId,
		BackChannelAuthenticationRequest request,
		TimeSpan expiresIn)
	{
		return storage.SetAsync(
			keyFactory.BackChannelAuthenticationRequestKey(requestId),
			request,
			new() { AbsoluteExpirationRelativeToNow = expiresIn });
	}

	/// <summary>
	/// Atomically retrieves and removes a backchannel authentication request from storage.
	/// This prevents race conditions in poll mode where concurrent requests could both retrieve
	/// the same authentication request before removal, leading to duplicate token issuance.
	/// </summary>
	/// <param name="authenticationRequestId">The unique identifier of the authentication request to remove.</param>
	/// <returns>
	/// A task that returns the authentication request if it existed and was successfully removed;
	/// otherwise, null if the request was not found or already removed by another concurrent request.
	/// </returns>
	public Task<BackChannelAuthenticationRequest?> TryRemoveAsync(string authenticationRequestId)
	{
		return storage.GetAsync<BackChannelAuthenticationRequest>(
			keyFactory.BackChannelAuthenticationRequestKey(authenticationRequestId),
			removeOnRetrieval: true);
	}
}
