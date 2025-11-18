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
using Parameters = Abblix.Oidc.Server.Model.IntrospectionRequest.Parameters;


namespace Abblix.Oidc.Server.Mvc.Model;

/// <summary>
/// Represents a request for token introspection.
/// This record is used to determine the active state and meta-information about a token.
/// </summary>
public record IntrospectionRequest
{
	/// <summary>
	/// The token that the client wants to introspect.
	/// This is the actual string value of the token for which the introspection request is being made.
	/// </summary>
	[BindProperty(Name = Parameters.Token)]
	[Required]
	public string Token { get; set; } = null!;

	/// <summary>
	/// A hint about the type of the token submitted for introspection.
	/// This can help the introspection endpoint optimize the token lookup.
	/// If not provided, the endpoint may try various token types until it finds one that matches.
	/// </summary>
	[BindProperty(Name = Parameters.TokenTypeHint)]
	public string? TokenTypeHint { get; set; }

	/// <summary>
	/// Maps the properties of this introspection request to a <see cref="Core.IntrospectionRequest"/> object.
	/// This method is used to translate the request data into a format that can be processed by the core logic of the server.
	/// </summary>
	/// <returns>A <see cref="Core.IntrospectionRequest"/> object populated with data from this request.</returns>
	public Core.IntrospectionRequest Map()
	{
		return new Core.IntrospectionRequest
		{
			Token = Token,
			TokenTypeHint = TokenTypeHint,
		};
	}
}
