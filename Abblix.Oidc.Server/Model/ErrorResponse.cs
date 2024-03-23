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
