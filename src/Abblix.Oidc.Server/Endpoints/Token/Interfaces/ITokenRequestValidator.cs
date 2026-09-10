// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;



namespace Abblix.Oidc.Server.Endpoints.Token.Interfaces;

/// <summary>
/// Validates an incoming OAuth 2.0 token request (RFC 6749 section 3.2) against the rules required by the
/// requested <c>grant_type</c>: client authentication, grant ownership (e.g. an authorization code
/// MUST have been issued to the authenticated client per OIDC Core 1.0 section 3.1.3.2), redirect URI
/// equivalence for code exchange, scope and resource (RFC 8707) consistency, and PKCE verifier
/// matching (RFC 7636 section 4.5) where applicable.
/// </summary>
public interface ITokenRequestValidator
{
	/// <summary>
	/// Validates the request and returns a <see cref="ValidTokenRequest"/> ready for token issuance,
	/// or an <see cref="OidcError"/> using one of the codes from RFC 6749 section 5.2 (e.g. <c>invalid_grant</c>,
	/// <c>invalid_client</c>, <c>unsupported_grant_type</c>).
	/// </summary>
	/// <param name="tokenRequest">The token request to validate.</param>
	/// <param name="clientRequest">Supplementary information about the client making the request.</param>
	/// <param name="cancellationToken">Abandons validation when the caller stops waiting.</param>
	Task<Result<ValidTokenRequest, OidcError>> ValidateAsync(
		TokenRequest tokenRequest, ClientRequest clientRequest, CancellationToken cancellationToken);
}
