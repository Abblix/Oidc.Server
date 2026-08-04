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

namespace Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

/// <summary>
/// Applies the protocol-level encoding of an authorization response in the framework-agnostic core:
/// the <c>iss</c> (RFC 9207) and implicit/hybrid <c>scope</c> gating, and - when the client requested
/// a JARM (<c>*.jwt</c>) response mode - packing all response parameters into the <c>response</c> JWT
/// and resolving the plaintext delivery mode.
/// </summary>
/// <remarks>
/// Invoked from <see cref="IAuthorizationHandler"/> after the full request-processing chain (including
/// the session-management decorator that sets <c>session_state</c>) has completed, so the JWT captures
/// the final parameter set. It mutates the response in place: <see cref="SuccessfullyAuthenticated"/>
/// and <see cref="AuthorizationError"/> gain their <c>Issuer</c>/<c>Scope</c>/<c>ResponseJwt</c> and a
/// resolved <c>ResponseMode</c>. Interaction responses (login/consent/etc.) and non-redirectable errors
/// are left untouched. The transport layer then only maps the encoded response onto its wire DTO.
/// </remarks>
public interface IAuthorizationResponseEncoder
{
	/// <summary>
	/// Encodes the supplied authorization response in place. No-op for response types that are not
	/// delivered to the client's redirect URI.
	/// </summary>
	/// <param name="response">The processed authorization response to encode.</param>
	Task EncodeAsync(AuthorizationResponse response);
}
