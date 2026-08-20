// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

/// <summary>
/// Defines the interface for processing authorization requests according to OpenID Connect and OAuth 2.0 specifications.
/// It handles the end-user's authentication, authorization decision, and the issuance of authorization codes and tokens.
/// </summary>
/// <remarks>
/// The actual authentication methods and the process to obtain the end-user's authorization decision are
/// implementation-specific and not defined by this interface.
/// </remarks>
public interface IAuthorizationRequestProcessor
{
	/// <summary>
	/// Processes a valid authorization request, authenticates the end-user, obtains an authorization decision,
	/// and issues an authorization code or tokens.
	/// </summary>
	/// <param name="request">The valid authorization request to process.</param>
	/// <returns>A task that resolves to an <see cref="AuthorizationResponse"/> containing the outcome
	/// of the request processing.</returns>
	Task<AuthorizationResponse> ProcessAsync(ValidAuthorizationRequest request);
}
