// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
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
/// <param name="DefaultContentEncryptionAlgorithm">The content-encryption algorithm to use when the client did not
/// register one.</param>
public sealed record ClientJwtEncryption(
	string? KeyManagementAlgorithm,
	string? ContentEncryptionAlgorithm,
	string DefaultContentEncryptionAlgorithm)
{
	/// <summary>
	/// Policy for a signed/encrypted UserInfo response (OIDC Core section 5.3.2): encrypts when the client registered
	/// <c>userinfo_encrypted_response_alg</c>, using its <c>userinfo_encrypted_response_*</c> metadata.
	/// </summary>
	public static ClientJwtEncryption ForUserInfo(ClientInfo clientInfo, OidcOptions options) => new(
		clientInfo.UserInfoEncryptedResponseAlgorithm,
		clientInfo.UserInfoEncryptedResponseEncryption,
		options.DefaultContentEncryptionAlgorithm);

	/// <summary>
	/// Policy for an ID token or logout token: encrypts when the client registered
	/// <c>id_token_encrypted_response_alg</c>, using its <c>id_token_encrypted_response_*</c> metadata.
	/// </summary>
	public static ClientJwtEncryption ForIdentityToken(ClientInfo clientInfo, OidcOptions options) => new(
		clientInfo.IdentityTokenEncryptedResponseAlgorithm,
		clientInfo.IdentityTokenEncryptedResponseEncryption,
		options.DefaultContentEncryptionAlgorithm);

	/// <summary>
	/// Policy for a signed/encrypted token introspection response (RFC 9701): encrypts when the client registered
	/// <c>introspection_encrypted_response_alg</c>, using its <c>introspection_encrypted_response_*</c> metadata.
	/// </summary>
	public static ClientJwtEncryption ForIntrospection(ClientInfo clientInfo, OidcOptions options) => new(
		clientInfo.IntrospectionEncryptedResponseAlgorithm,
		clientInfo.IntrospectionEncryptedResponseEncryption,
		options.DefaultContentEncryptionAlgorithm);

	/// <summary>
	/// Policy for a JARM authorization response JWT: encrypts only when the client registered
	/// <c>authorization_encrypted_response_alg</c> (JARM section 2.2 / section 3 opt-in), falling back to
	/// <see cref="OidcOptions.DefaultAuthorizationResponseEncryptionAlgorithm"/> when
	/// <c>authorization_encrypted_response_enc</c> is omitted.
	/// </summary>
	/// <remarks>
	/// The fallback comes from its own setting rather than
	/// <see cref="OidcOptions.DefaultContentEncryptionAlgorithm"/>, because JARM section 3 names a different
	/// value for this response than the one the other client-addressed JWTs default to, and a client that
	/// registered only the key-management algorithm is entitled to the one the specification named.
	/// </remarks>
	public static ClientJwtEncryption ForJarm(ClientInfo clientInfo, OidcOptions options) => new(
		clientInfo.AuthorizationEncryptedResponseAlgorithm,
		clientInfo.AuthorizationEncryptedResponseEncryption,
		options.DefaultAuthorizationResponseEncryptionAlgorithm);
}
