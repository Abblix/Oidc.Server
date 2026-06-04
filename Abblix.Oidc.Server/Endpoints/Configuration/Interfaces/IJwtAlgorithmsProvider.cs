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

namespace Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;

/// <summary>
/// Provides metadata about supported JWT signing and validation algorithms for OpenID Connect discovery.
/// </summary>
public interface IJwtAlgorithmsProvider
{
	/// <summary>
	/// Lists the signing algorithms supported for ID tokens and UserInfo responses.
	/// </summary>
	IEnumerable<string> SignedResponseAlgorithmsSupported { get; }

	/// <summary>
	/// Lists the signing algorithms supported for validating signed requests and authentication.
	/// </summary>
	IEnumerable<string> SigningAlgorithmsSupported { get; }

	/// <summary>
	/// Lists the JWS signing algorithms the authorization server accepts on inbound DPoP
	/// proofs (RFC 9449 §5.1 <c>dpop_signing_alg_values_supported</c>): the intersection
	/// of <see cref="SigningAlgorithmsSupported"/> with the static DPoP-compatible
	/// whitelist. The validator-side set is the source — the AS verifies proofs the
	/// client signs, it does not issue them.
	/// </summary>
	IEnumerable<string> DpopSigningAlgorithmsSupported { get; }

	/// <summary>
	/// Lists the JWE key-management algorithms (the <c>alg</c> values) the authorization server
	/// accepts when a client encrypts a request object to the server (RFC 9101 §6.1),
	/// advertised via <c>request_object_encryption_alg_values_supported</c>.
	/// </summary>
	IEnumerable<string> RequestObjectEncryptionAlgValuesSupported { get; }

	/// <summary>
	/// Lists the JWE content-encryption algorithms (the <c>enc</c> values) the authorization server
	/// accepts when a client encrypts a request object to the server (RFC 9101 §6.1),
	/// advertised via <c>request_object_encryption_enc_values_supported</c>.
	/// </summary>
	IEnumerable<string> RequestObjectEncryptionEncValuesSupported { get; }

	/// <summary>
	/// Lists the JWS algorithms the authorization server uses to sign JARM authorization responses,
	/// advertised via <c>authorization_signing_alg_values_supported</c> (JARM §4).
	/// </summary>
	IEnumerable<string> AuthorizationSigningAlgValuesSupported { get; }

	/// <summary>
	/// Lists the JWE key-management algorithms (the <c>alg</c> values) the authorization server can use to
	/// encrypt JARM authorization responses, advertised via <c>authorization_encryption_alg_values_supported</c>
	/// (JARM §4).
	/// </summary>
	IEnumerable<string> AuthorizationEncryptionAlgValuesSupported { get; }

	/// <summary>
	/// Lists the JWE content-encryption algorithms (the <c>enc</c> values) the authorization server can use to
	/// encrypt JARM authorization responses, advertised via <c>authorization_encryption_enc_values_supported</c>
	/// (JARM §4).
	/// </summary>
	IEnumerable<string> AuthorizationEncryptionEncValuesSupported { get; }

	/// <summary>
	/// Lists the JWS algorithms the authorization server uses to sign JWT introspection responses,
	/// advertised via <c>introspection_signing_alg_values_supported</c> (RFC 9701 §7).
	/// </summary>
	IEnumerable<string> IntrospectionSigningAlgValuesSupported { get; }

	/// <summary>
	/// Lists the JWE key-management algorithms (the <c>alg</c> values) the authorization server can use to encrypt
	/// JWT introspection responses, advertised via <c>introspection_encryption_alg_values_supported</c>
	/// (RFC 9701 §7).
	/// </summary>
	IEnumerable<string> IntrospectionEncryptionAlgValuesSupported { get; }

	/// <summary>
	/// Lists the JWE content-encryption algorithms (the <c>enc</c> values) the authorization server can use to
	/// encrypt JWT introspection responses, advertised via <c>introspection_encryption_enc_values_supported</c>
	/// (RFC 9701 §7).
	/// </summary>
	IEnumerable<string> IntrospectionEncryptionEncValuesSupported { get; }
}
