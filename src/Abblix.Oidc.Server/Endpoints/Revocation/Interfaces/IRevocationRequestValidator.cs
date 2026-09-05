// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Model;



namespace Abblix.Oidc.Server.Endpoints.Revocation.Interfaces;

/// <summary>
/// Represents the capability to validate revocation requests.
/// The authorization server validates client credentials (for confidential clients) and checks if the token was issued
/// to the requesting client. If validation fails, the request is refused, and an error message is provided to
/// the client by the authorization server.
/// </summary>
public interface IRevocationRequestValidator
{
	/// <summary>
	/// Validates a revocation request.
	/// </summary>
	/// <param name="revocationRequest">The revocation request to be validated.</param>
	/// <param name="clientRequest">Additional client request information for contextual validation.</param>
	/// <returns>A task representing the asynchronous operation with the validation result.</returns>
	Task<Result<ValidRevocationRequest, OidcError>> ValidateAsync(
		RevocationRequest revocationRequest,
		ClientRequest clientRequest);
}
