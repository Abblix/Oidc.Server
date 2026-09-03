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
/// Parameters of an OAuth 2.0 token introspection request (RFC 7662 section 2.1) sent to the
/// <c>introspection_endpoint</c>, used by protected resources to determine the active state and metadata
/// of a token. Client authentication is required and is supplied alongside this payload.
/// </summary>
public record IntrospectionRequest
{
	/// <summary>
	/// Wire-level parameter names accepted at the OAuth 2.0 introspection endpoint (RFC 7662 section 2.1).
	/// </summary>
	public static class Parameters
	{
		/// <summary>The <c>token</c> introspection request parameter carrying the token to be inspected.
		/// </summary>
		public const string Token = "token";

		/// <summary>The <c>token_type_hint</c> introspection request parameter advising which token type
		/// the server should try first.</summary>
		public const string TokenTypeHint = "token_type_hint";
	}

	/// <summary>
	/// The <c>token</c> parameter (RFC 7662 section 2.1): the token string for which the client is requesting
	/// introspection metadata. Required.
	/// </summary>
	[JsonPropertyName(Parameters.Token)]
	[Required]
	public string Token { get; set; } = null!;

	/// <summary>
	/// The optional <c>token_type_hint</c> (RFC 7662 section 2.1) telling the server which token type to try first,
	/// for example <c>access_token</c> or <c>refresh_token</c>. The server may still inspect other token types.
	/// </summary>
	[JsonPropertyName(Parameters.TokenTypeHint)]
	public string? TokenTypeHint { get; set; }
}
