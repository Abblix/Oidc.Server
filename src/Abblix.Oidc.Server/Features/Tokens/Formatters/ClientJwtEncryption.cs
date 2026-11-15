// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.Features.Tokens.Formatters;

/// <summary>
/// The encryption policy a caller hands to <see cref="ClientJwtFormatter"/> when formatting a client-addressed JWT.
/// It makes explicit which registered client metadata governs encryption, so the formatter no longer has to infer it
/// from the token type. Each client-JWT type (UserInfo, ID token, JARM authorization response, introspection)
/// supplies its own policy via the static factories below.
/// </summary>
/// <param name="KeyManagementAlgorithm">The client's registered <c>*_encrypted_response_alg</c>, or <c>null</c> when
/// the client did not register one. Only a registered algorithm asks for encryption, and the JWT is then encrypted under
/// exactly it (OpenID Connect Dynamic Client Registration 1.0 section 2: "The default, if omitted, is that no encryption
/// is performed").</param>
/// <param name="ContentEncryptionAlgorithm">The client's registered <c>*_encrypted_response_enc</c>, or <c>null</c>
/// to fall back to <see cref="DefaultContentEncryptionAlgorithm"/>.</param>
/// <param name="UnsignedIsClaimsSet">Whether a JWT registered unsigned is encrypted as its claims set (RFC 7519 section
/// 3) rather than as an unsigned JWS inside the JWE: OpenID Connect Core 1.0 section 5.3.2 has a UserInfo response that
/// "MAY be encrypted without also being signed", while section 2 has an encrypted ID token "signed then encrypted, with
/// the result being a Nested JWT".</param>
public sealed record ClientJwtEncryption(
	string? KeyManagementAlgorithm,
	string? ContentEncryptionAlgorithm,
	bool UnsignedIsClaimsSet = false)
{
	/// <summary>
	/// The content encryption algorithm a client JWT is encrypted with when the client registered its
	/// <c>*_encrypted_response_alg</c> without the matching <c>*_encrypted_response_enc</c>.
	/// </summary>
	/// <remarks>
	/// Every specification names the same value and none lets the server choose another: OpenID Connect Dynamic Client
	/// Registration 1.0 section 2, "If id_token_encrypted_response_alg is specified, the default
	/// id_token_encrypted_response_enc value is A128CBC-HS256", and likewise for userinfo; RFC 9701 section 6 for
	/// introspection, "The default, if omitted, is A128CBC-HS256"; JWT Secured Authorization Response Mode section 3,
	/// "if authorization_encrypted_response_alg is specified, the default for this value is A128CBC-HS256". The
	/// registration response carries no enc the client omitted, so the client expects this value and no other.
	/// </remarks>
	public const string DefaultContentEncryptionAlgorithm = EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256;

	/// <summary>
	/// The content-encryption algorithm the JWT is encrypted with: the registered one, else the default.
	/// </summary>
	public string ContentEncryptionAlgorithmInUse => ContentEncryptionAlgorithm ?? DefaultContentEncryptionAlgorithm;

	/// <summary>
	/// Policy for a signed/encrypted UserInfo response (OIDC Core section 5.3.2): encrypts when the client registered
	/// <c>userinfo_encrypted_response_alg</c>, using its <c>userinfo_encrypted_response_*</c> metadata.
	/// </summary>
	public static ClientJwtEncryption ForUserInfo(ClientInfo clientInfo) => new(
		clientInfo.UserInfoEncryptedResponseAlgorithm,
		clientInfo.UserInfoEncryptedResponseEncryption,
		UnsignedIsClaimsSet: true);

	/// <summary>
	/// Policy for an ID token or logout token: encrypts when the client registered
	/// <c>id_token_encrypted_response_alg</c>, using its <c>id_token_encrypted_response_*</c> metadata.
	/// </summary>
	public static ClientJwtEncryption ForIdentityToken(ClientInfo clientInfo) => new(
		clientInfo.IdentityTokenEncryptedResponseAlgorithm,
		clientInfo.IdentityTokenEncryptedResponseEncryption);

	/// <summary>
	/// Policy for a signed/encrypted token introspection response (RFC 9701): encrypts when the client registered
	/// <c>introspection_encrypted_response_alg</c>, using its <c>introspection_encrypted_response_*</c> metadata.
	/// </summary>
	public static ClientJwtEncryption ForIntrospection(ClientInfo clientInfo) => new(
		clientInfo.IntrospectionEncryptedResponseAlgorithm,
		clientInfo.IntrospectionEncryptedResponseEncryption);

	/// <summary>
	/// Policy for a JARM authorization response JWT: encrypts only when the client registered
	/// <c>authorization_encrypted_response_alg</c> (JARM section 2.2 / section 3 opt-in), using its
	/// <c>authorization_encrypted_response_*</c> metadata.
	/// </summary>
	public static ClientJwtEncryption ForJarm(ClientInfo clientInfo) => new(
		clientInfo.AuthorizationEncryptedResponseAlgorithm,
		clientInfo.AuthorizationEncryptedResponseEncryption);
}
