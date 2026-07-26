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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;



namespace Abblix.Oidc.Server.Endpoints.Token.Interfaces;

/// <summary>
/// Validates an incoming OAuth 2.0 token request (RFC 6749 §3.2) against the rules required by the
/// requested <c>grant_type</c>: client authentication, grant ownership (e.g. an authorization code
/// MUST have been issued to the authenticated client per OIDC Core 1.0 §3.1.3.2), redirect URI
/// equivalence for code exchange, scope and resource (RFC 8707) consistency, and PKCE verifier
/// matching (RFC 7636 §4.5) where applicable.
/// </summary>
public interface ITokenRequestValidator
{
	/// <summary>
	/// Validates the request and returns a <see cref="ValidTokenRequest"/> ready for token issuance,
	/// or an <see cref="OidcError"/> using one of the codes from RFC 6749 §5.2 (e.g. <c>invalid_grant</c>,
	/// <c>invalid_client</c>, <c>unsupported_grant_type</c>).
	/// </summary>
	[Obsolete("Implement and call the overload taking a CancellationToken. This one is kept so an existing " +
	          "implementation keeps working, and will be removed in the next major version.")]
	Task<Result<ValidTokenRequest, OidcError>> ValidateAsync(TokenRequest tokenRequest, ClientRequest clientRequest)
		=> ValidateAsync(tokenRequest, clientRequest, CancellationToken.None);

	/// <inheritdoc cref="ValidateAsync(TokenRequest, ClientRequest)"/>
	/// <param name="tokenRequest">The token request to validate.</param>
	/// <param name="clientRequest">Supplementary information about the client making the request.</param>
	/// <param name="cancellationToken">Abandons validation when the caller stops waiting.</param>
	/// <remarks>
	/// This is the member an implementation provides. The obsolete overload above defaults to forwarding here,
	/// so a caller still holding the old signature keeps working, while an implementation that provided only
	/// the old one fails to compile rather than silently never receiving the token.
	/// </remarks>
	Task<Result<ValidTokenRequest, OidcError>> ValidateAsync(
		TokenRequest tokenRequest, ClientRequest clientRequest, CancellationToken cancellationToken);
}
