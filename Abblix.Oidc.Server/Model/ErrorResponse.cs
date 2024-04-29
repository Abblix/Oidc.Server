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

using System.Text.Json.Serialization;

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Represents a standardized error response, commonly used in web APIs and OAuth2/OpenID Connect protocols.
/// </summary>
public record ErrorResponse(string Error, string ErrorDescription)
{
	/// <summary>
	/// The error code representing the specific type of error encountered.
	/// This is a single ASCII error code from the predefined set of OAuth2/OpenID Connect standard codes.
	/// </summary>
	[JsonPropertyName("error")]
	public string Error { get; init; } = Error;

	/// <summary>
	/// A human-readable text providing additional information about the error.
	/// This description is meant to aid in diagnosing the error and is not intended for displaying to end-users.
	/// </summary>
	[JsonPropertyName("error_description")]
	public string ErrorDescription { get; init; } = ErrorDescription;
}
