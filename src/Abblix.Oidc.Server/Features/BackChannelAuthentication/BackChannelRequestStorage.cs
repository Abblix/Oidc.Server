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
	/// Retrieves and removes a backchannel authentication request from storage, through the store's claim
	/// protocol. The claim is what keeps two polls from both being told they took the same request; the
	/// per-key gate around the removal is what keeps a contended key from ending with NEITHER of them
	/// told. The value is read under that same hold, so a poll is handed the bytes the removal took rather
	/// than the ones it read on its way in.
	/// <para>
	/// That is the whole of what the hold buys, and it is narrower than "no write is lost". Only the read
	/// and the removal are inside it: <see cref="UpdateAsync"/> is a plain set on this key and takes no
	/// gate, so a write from the CIBA grant handler's next-poll bump can still land after the in-gate read
	/// and be destroyed by the removal without ever being seen - which that handler's own remarks already
	/// treat as an ordinary race. Closing THAT needs the writers to take the gate too, not a wider claim
	/// here.
	/// </para>
	/// </summary>
	/// <param name="authenticationRequestId">The unique identifier of the authentication request to remove.</param>
	/// <returns>
	/// A task that returns the authentication request when this caller removed it and still held its own
	/// claim afterwards. Null otherwise, and that covers more than a competitor: the request not being
	/// there, and a claim that expired while a store call was in flight - the second on one caller with
	/// nobody to lose to, its outcome being the request gone with nobody able to be told they took it. A
	/// store call that fails after the removal raises instead of answering.
	/// </returns>
	public Task<BackChannelAuthenticationRequest?> TryRemoveAsync(string authenticationRequestId)
	{
		return storage.GetAsync<BackChannelAuthenticationRequest>(
			keyFactory.BackChannelAuthenticationRequestKey(authenticationRequestId),
			removeOnRetrieval: true);
	}
}
