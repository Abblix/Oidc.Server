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
public class BackChannelAuthenticationStorage(
	IEntityStorage storage,
	IAuthenticationRequestIdGenerator authenticationRequestIdGenerator,
	IEntityStorageKeyFactory keyFactory) : IBackChannelAuthenticationStorage
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
		return storage.GetAsync<BackChannelAuthenticationRequest>(
			keyFactory.BackChannelAuthenticationRequestKey(authenticationRequestId),
			true);
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
	/// Removes a backchannel authentication request from storage using its unique identifier.
	/// This method allows for cleaning up expired or completed authentication requests.
	/// </summary>
	/// <param name="authenticationRequestId">The unique identifier of the authentication request to remove.</param>
	/// <returns>
	/// A task that completes when the request is removed from storage.
	/// </returns>
	public Task RemoveAsync(string authenticationRequestId)
		=> storage.RemoveAsync(keyFactory.BackChannelAuthenticationRequestKey(authenticationRequestId));

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
