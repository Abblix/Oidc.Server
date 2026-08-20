// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces;

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
	/// <param name="request">The <see cref="Model.AuthorizationRequest"/> instance to be stored.</param>
	/// <param name="expiresIn">The duration after which the stored request should expire and be considered invalid.</param>
	/// <returns>A <see cref="Task"/> that, when completed successfully,
	/// yields a <see cref="PushedAuthorizationResponse"/> containing the unique identifier of the stored request
	/// and its expiration information.
	/// </returns>
	Task<PushedAuthorizationResponse> StoreAsync(Model.AuthorizationRequest request, TimeSpan expiresIn);

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
	/// the <see cref="Model.AuthorizationRequest"/> associated with the specified identifier,
	/// or null if no such request exists or if it has expired.</returns>
	Task<Model.AuthorizationRequest?> TryGetAsync(Uri requestUri, bool shouldRemove = false);
}
