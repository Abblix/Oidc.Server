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

using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;
using Core = Abblix.Oidc.Server.Model;
using Parameters = Abblix.Oidc.Server.Model.RevocationRequest.Parameters;


namespace Abblix.Oidc.Server.Mvc.Model;

/// <summary>
/// Represents a request for token revocation, extending from <see cref="ClientRequest"/>.
/// This record is used to invalidate a token, making it no longer usable for authorization purposes.
/// </summary>
public record RevocationRequest : ClientRequest
{
	/// <summary>
	/// The token that the client wants to revoke.
	/// This is the actual string value of the token which is intended to be invalidated and discontinued for further use.
	/// </summary>
	[BindProperty(SupportsGet = true, Name = Parameters.Token)]
	[Required]
	public string Token { get; set; } = default!;

	/// <summary>
	/// A hint about the type of the token submitted for revocation.
	/// Providing this information can help the revocation endpoint handle the token more efficiently.
	/// If omitted, the server may assume a default token type.
	/// </summary>
	[BindProperty(SupportsGet = true, Name = Parameters.TokenTypeHint)]
	public string? TokenTypeHint { get; set; } // TODO consider to use enum here

	/// <summary>
	/// Maps the properties of this revocation request to a <see cref="Core.RevocationRequest"/> object.
	/// This method is used to translate the request data into a format that can be processed by the core logic of the server.
	/// </summary>
	/// <returns>A <see cref="Core.RevocationRequest"/> object populated with data from this request.</returns>
	public new Core.RevocationRequest Map()
	{
		return new Core.RevocationRequest
		{
			Token = Token,
			TokenTypeHint = TokenTypeHint,
		};
	}
}
