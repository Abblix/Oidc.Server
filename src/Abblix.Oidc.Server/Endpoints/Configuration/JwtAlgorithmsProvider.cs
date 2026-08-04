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

using Abblix.Jwt;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Oidc.Server.Features.DPoP;

namespace Abblix.Oidc.Server.Endpoints.Configuration;

/// <summary>
/// Provides JWT algorithm metadata by delegating to JWT creator and validator.
/// </summary>
public sealed class JwtAlgorithmsProvider(
	IJsonWebTokenCreator jwtCreator,
	IJsonWebTokenValidator jwtValidator) : IJwtAlgorithmsProvider
{
	/// <summary>
	/// HMAC algorithms are excluded from every client-addressed response-signing list: per
	/// OIDC Core §10.1 an HS* signature uses the client_secret as the key, but this server
	/// persists client secrets as SHA-512 hashes (except the client_secret_jwt case), so it
	/// cannot derive the HMAC key at signing time. Advertising HS* let a client register it
	/// via DCR and then fail with a server error on the first issued token. The JWT layer
	/// itself still supports HMAC signers - the constraint is about key availability here,
	/// not signing capability.
	/// </summary>
	private static readonly string[] HmacAlgorithms =
		[SigningAlgorithms.HS256, SigningAlgorithms.HS384, SigningAlgorithms.HS512];

	private IEnumerable<string> ClientAddressedSigningAlgorithms
		=> jwtCreator.SignedResponseAlgorithmsSupported.Where(alg => !HmacAlgorithms.Contains(alg));

	/// <inheritdoc />
	public IEnumerable<string> SignedResponseAlgorithmsSupported => ClientAddressedSigningAlgorithms;

	/// <inheritdoc />
	public IEnumerable<string> SigningAlgorithmsSupported => jwtValidator.SigningAlgorithmsSupported;

	/// <summary>
	/// RFC 8414 §2 and OpenID Connect Discovery 1.0 §3 both state the value "none" MUST NOT appear
	/// in token_endpoint_auth_signing_alg_values_supported - a client authenticates by signing a
	/// JWT assertion, so an unsecured assertion would prove nothing. HS* stay because
	/// client_secret_jwt legitimately keys on the shared client secret.
	/// </summary>
	public IEnumerable<string> TokenEndpointAuthSigningAlgValuesSupported
		=> jwtValidator.SigningAlgorithmsSupported.Where(alg => alg != SigningAlgorithms.None);

	/// <summary>
	/// CIBA Core §7.1.1 requires the signed backchannel authentication request to use an asymmetric
	/// algorithm, so both "none" and the symmetric HS* algorithms are excluded here.
	/// </summary>
	public IEnumerable<string> BackChannelAuthenticationRequestSigningAlgValuesSupported
		=> jwtValidator.SigningAlgorithmsSupported.Where(
			alg => alg != SigningAlgorithms.None && !HmacAlgorithms.Contains(alg));

	/// <inheritdoc />
	public IEnumerable<string> DpopSigningAlgorithmsSupported
		=> jwtValidator.SigningAlgorithmsSupported.Where(DPoPAlgorithms.Allowed.Contains);

	/// <inheritdoc />
	public IEnumerable<string> RequestObjectEncryptionAlgValuesSupported => jwtValidator.EncryptionAlgorithmsSupported;

	/// <inheritdoc />
	public IEnumerable<string> RequestObjectEncryptionEncValuesSupported => jwtValidator.EncryptionMethodsSupported;

	/// <inheritdoc />
	public IEnumerable<string> AuthorizationSigningAlgValuesSupported => ClientAddressedSigningAlgorithms;

	/// <inheritdoc />
	public IEnumerable<string> AuthorizationEncryptionAlgValuesSupported => jwtValidator.EncryptionAlgorithmsSupported;

	/// <inheritdoc />
	public IEnumerable<string> AuthorizationEncryptionEncValuesSupported => jwtValidator.EncryptionMethodsSupported;

	/// <inheritdoc />
	public IEnumerable<string> IntrospectionSigningAlgValuesSupported => ClientAddressedSigningAlgorithms;

	/// <inheritdoc />
	public IEnumerable<string> IntrospectionEncryptionAlgValuesSupported => jwtValidator.EncryptionAlgorithmsSupported;

	/// <inheritdoc />
	public IEnumerable<string> IntrospectionEncryptionEncValuesSupported => jwtValidator.EncryptionMethodsSupported;
}
