// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
