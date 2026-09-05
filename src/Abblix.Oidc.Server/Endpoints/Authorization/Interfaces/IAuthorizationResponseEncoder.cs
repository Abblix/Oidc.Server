// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
