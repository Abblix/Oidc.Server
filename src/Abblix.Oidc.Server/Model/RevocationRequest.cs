// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;


namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Parameters of an OAuth 2.0 token revocation request (RFC 7009 §2.1) sent to the
/// <c>revocation_endpoint</c>. Client authentication is required and is supplied alongside this payload.
/// </summary>
public record RevocationRequest
{
	/// <summary>
	/// Wire-level parameter names accepted at the OAuth 2.0 revocation endpoint (RFC 7009 §2.1).
	/// </summary>
	public static class Parameters
	{
		/// <summary>The <c>token</c> revocation request parameter carrying the access or refresh token
		/// to be revoked.</summary>
		public const string Token = "token";

		/// <summary>The <c>token_type_hint</c> revocation request parameter advising whether the token is
		/// an <c>access_token</c> or a <c>refresh_token</c>.</summary>
		public const string TokenTypeHint = "token_type_hint";
	}

	/// <summary>
	/// The <c>token</c> parameter (RFC 7009 §2.1): the access token or refresh token string the client
	/// is asking the authorization server to revoke. Required.
	/// </summary>
	[JsonPropertyName(Parameters.Token)]
	[Required]
	public string Token { get; set; } = null!;

	/// <summary>
	/// The optional <c>token_type_hint</c> (RFC 7009 §2.1) advising whether <see cref="Token"/> is an
	/// <c>access_token</c> or <c>refresh_token</c>, allowing the server to look it up faster.
	/// </summary>
	[JsonPropertyName(Parameters.TokenTypeHint)]
	public string? TokenTypeHint { get; set; }
}
