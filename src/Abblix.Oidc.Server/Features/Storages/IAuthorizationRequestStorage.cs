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
	/// which is what narrows the window in which it is retrieved twice. RFC 9126 puts the MUST on the
	/// client - "the client MUST only use a request_uri value once" (Section 4, Authorization Request) -
	/// and asks the authorization server for no more than a SHOULD, twice: Section 4 hedges it with a MAY
	/// for a user reloading their user agent, and Section 7.3 states it plainly, "the authorization
	/// server SHOULD make the request URIs one-time use". Consuming it here is therefore this library's
	/// choice, taken on the specification's recommendation rather than on its requirement. Narrows rather
	/// than closes: the returns block says what a null covers.
	/// </summary>
	/// <param name="requestUri">The unique identifier of the authorization request, typically a URI,
	/// used to locate the request in storage.</param>
	/// <param name="shouldRemove">Specifies whether the request should be removed from storage on
	/// retrieval, for the one-time use scenarios where a second retrieval must not succeed.</param>
	/// <returns>A <see cref="Task"/> that, when completed successfully, yields
	/// the <see cref="Model.AuthorizationRequest"/> associated with the specified identifier,
	/// or null. With <paramref name="shouldRemove"/> set, null is wider than "no such request": it also
	/// covers the entry having expired, another caller having removed it, and a claim that expired
	/// mid-protocol on a single caller with nobody to lose to. A store call that fails after the removal
	/// raises instead of answering.</returns>
	Task<Model.AuthorizationRequest?> TryGetAsync(Uri requestUri, bool shouldRemove = false);
}
