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

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;

/// <summary>
/// Defines the contract for a storage system responsible for persisting and retrieving
/// backchannel authentication requests in the context of Client-Initiated Backchannel Authentication (CIBA).
/// </summary>
public interface IBackChannelAuthenticationStorage
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
	/// Removes a backchannel authentication request from the storage system using its unique identifier.
	/// This method allows for cleanup of expired or completed authentication requests.
	/// </summary>
	/// <param name="authenticationRequestId">The unique identifier of the authentication request to remove.</param>
	/// <returns>
	/// A task that completes when the request is removed from storage.
	/// </returns>
	Task RemoveAsync(string authenticationRequestId);
}
