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
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.Features.Tokens.Formatters;

/// <summary>
/// The encryption policy a caller hands to <see cref="ClientJwtFormatter"/> when formatting a client-addressed JWT.
/// It makes explicit which registered client metadata governs encryption, so the formatter no longer has to infer it
/// from the token type. Each client-JWT class (UserInfo, ID token, JARM authorization response, introspection)
/// supplies its own policy via the static factories below.
/// </summary>
/// <param name="KeyManagementAlgorithm">The client's registered <c>*_encrypted_response_alg</c>, or <c>null</c> when
/// the client did not register one.</param>
/// <param name="ContentEncryptionAlgorithm">The client's registered <c>*_encrypted_response_enc</c>, or <c>null</c>
/// to fall back to <see cref="DefaultContentEncryptionAlgorithm"/>.</param>
/// <param name="DefaultContentEncryptionAlgorithm">The content-encryption algorithm to use when the client did not
/// register one.</param>
/// <param name="RequireRegisteredAlgorithm">When <c>true</c> the JWT is encrypted only if the client registered a
/// key-management algorithm (and the client's encryption keys are not even resolved otherwise) — the JARM §2.2 / §3
/// opt-in rule. When <c>false</c> the JWT is encrypted whenever the client published encryption keys.</param>
public sealed record ClientJwtEncryption(
	string? KeyManagementAlgorithm,
	string? ContentEncryptionAlgorithm,
	string DefaultContentEncryptionAlgorithm,
	bool RequireRegisteredAlgorithm)
{
	/// <summary>
	/// Policy for a signed/encrypted UserInfo response (OIDC Core §5.3.2): encrypts whenever the client published
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
	/// Policy for a JARM authorization response JWT: encrypts only when the client registered
	/// <c>authorization_encrypted_response_alg</c> (JARM §2.2 / §3 opt-in), defaulting the content-encryption to
	/// <c>A128CBC-HS256</c> when <c>authorization_encrypted_response_enc</c> is omitted (JARM §3).
	/// </summary>
	public static ClientJwtEncryption ForJarm(ClientInfo clientInfo) => new(
		clientInfo.AuthorizationEncryptedResponseAlgorithm,
		clientInfo.AuthorizationEncryptedResponseEncryption,
		EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256,
		RequireRegisteredAlgorithm: true);
}
