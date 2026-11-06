// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Serialization;

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Represents a standardized error response, commonly used in web APIs and OAuth2/OpenID Connect protocols.
/// </summary>
public readonly record struct ErrorResponse(string Error, string ErrorDescription)
{
	/// <summary>
	/// Wire-level member names of the error response body.
	/// </summary>
	public static class Parameters
	{
		/// <summary>The <c>error</c> code identifying the failure.</summary>
		public const string Error = "error";
		/// <summary>The <c>error_description</c> human-readable failure detail.</summary>
		public const string ErrorDescription = "error_description";
	}

	/// <summary>
	/// The error code representing the specific type of error encountered.
	/// This is a single ASCII error code from the predefined set of OAuth2/OpenID Connect standard codes.
	/// </summary>
	[JsonPropertyName(Parameters.Error)]
	public string Error { get; init; } = Error;

	/// <summary>
	/// A human-readable text providing additional information about the error.
	/// This description is meant to aid in diagnosing the error and is not intended for displaying to end-users.
	/// </summary>
	[JsonPropertyName(Parameters.ErrorDescription)]
	public string ErrorDescription { get; init; } = ErrorDescription;
}
