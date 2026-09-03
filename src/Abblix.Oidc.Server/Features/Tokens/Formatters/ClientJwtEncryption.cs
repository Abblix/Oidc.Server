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
/// the client did not register one.</param>
/// <param name="ContentEncryptionAlgorithm">The client's registered <c>*_encrypted_response_enc</c>, or <c>null</c>
/// to fall back to <see cref="DefaultContentEncryptionAlgorithm"/>.</param>
/// <param name="DefaultContentEncryptionAlgorithm">The content-encryption algorithm to use when the client did not
/// register one.</param>
/// <param name="RequireRegisteredAlgorithm">When <c>true</c> the JWT is encrypted only if the client registered a
/// key-management algorithm (and the client's encryption keys are not even resolved otherwise) - the JARM section 2.2 / section 3
/// opt-in rule. When <c>false</c> the JWT is encrypted whenever the client published encryption keys.</param>
public sealed record ClientJwtEncryption(
	string? KeyManagementAlgorithm,
	string? ContentEncryptionAlgorithm,
	string DefaultContentEncryptionAlgorithm,
	bool RequireRegisteredAlgorithm)
{
	/// <summary>
	/// Policy for a signed/encrypted UserInfo response (OIDC Core section 5.3.2): encrypts whenever the client published
	/// encryption keys, using its <c>userinfo_encrypted_response_*</c> metadata.
	/// </summary>
	public static ClientJwtEncryption ForUserInfo(ClientInfo clientInfo, OidcOptions options) => new(
		clientInfo.UserInfoEncryptedResponseAlgorithm,
		clientInfo.UserInfoEncryptedResponseEncryption,
		options.DefaultContentEncryptionAlgorithm,
		RequireRegisteredAlgorithm: false);

	/// <summary>
	/// Policy for an ID token or logout token: encrypts whenever the client published encryption keys, using its
	/// <c>id_token_encrypted_response_*</c> metadata.
	/// </summary>
	public static ClientJwtEncryption ForIdentityToken(ClientInfo clientInfo, OidcOptions options) => new(
		clientInfo.IdentityTokenEncryptedResponseAlgorithm,
		clientInfo.IdentityTokenEncryptedResponseEncryption,
		options.DefaultContentEncryptionAlgorithm,
		RequireRegisteredAlgorithm: false);

	/// <summary>
	/// Policy for a signed/encrypted token introspection response (RFC 9701): encrypts whenever the client published
	/// encryption keys, using its <c>introspection_encrypted_response_*</c> metadata.
	/// </summary>
	public static ClientJwtEncryption ForIntrospection(ClientInfo clientInfo, OidcOptions options) => new(
		clientInfo.IntrospectionEncryptedResponseAlgorithm,
		clientInfo.IntrospectionEncryptedResponseEncryption,
		options.DefaultContentEncryptionAlgorithm,
		RequireRegisteredAlgorithm: false);

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
		options.DefaultAuthorizationResponseEncryptionAlgorithm,
		RequireRegisteredAlgorithm: true);
}
