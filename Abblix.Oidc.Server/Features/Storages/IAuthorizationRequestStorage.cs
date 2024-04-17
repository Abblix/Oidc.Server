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
