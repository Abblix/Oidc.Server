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

using Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// Provides mechanisms for securely storing and retrieving OAuth 2.0 authorization requests.
/// This interface abstracts the storage layer, allowing for implementation-specific details
/// such as database, cache or filesystem storage.
/// </summary>
public interface IAuthorizationRequestStorage
{
	/// <summary>
	/// Asynchronously stores the provided authorization request in a secure manner and returns a unique identifier
	/// for it. This identifier can be used to retrieve the request at a later time, facilitating mechanisms
	/// like the Pushed Authorization Request (PAR). This method also accepts an expiration time for the request,
	/// allowing the storage mechanism to automatically invalidate the request after a certain period.
	/// </summary>
	/// <param name="request">The <see cref="AuthorizationRequest"/> instance to be stored.</param>
	/// <param name="expiresIn">The duration after which the stored request should expire and be considered invalid.</param>
	/// <returns>A <see cref="Task"/> that, when completed successfully,
	/// yields a <see cref="PushedAuthorizationResponse"/> containing the unique identifier of the stored request
	/// and its expiration information.
	/// </returns>
	Task<PushedAuthorizationResponse> StoreAsync(AuthorizationRequest request, TimeSpan expiresIn);

	/// <summary>
	/// Asynchronously retrieves an authorization request using a previously stored unique identifier.
	/// This method facilitates the retrieval of authorization requests for further processing or validation.
	/// The shouldRemove parameter controls whether the request is deleted from storage upon retrieval,
	/// ensuring it cannot be retrieved again, which is essential for one-time use scenarios like authorization codes.
	/// </summary>
	/// <param name="requestUri">The unique identifier of the authorization request, typically a URI,
	/// used to locate the request in storage.</param>
	/// <param name="shouldRemove">Specifies whether the request should be removed from storage on retrieval.
	/// This is useful for one-time use scenarios, ensuring that an authorization request cannot be reused.</param>
	/// <returns>A <see cref="Task"/> that, when completed successfully, yields
	/// the <see cref="AuthorizationRequest"/> associated with the specified identifier,
	/// or null if no such request exists or if it has expired.</returns>
	Task<AuthorizationRequest?> TryGetAsync(Uri requestUri, bool shouldRemove = false);
}
