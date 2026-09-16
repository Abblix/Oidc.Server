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
/// The answer to a logout request the end user has not yet agreed to: the standard error shape, plus the value the
/// host's page sends back with their answer.
/// </summary>
/// <param name="Error">The error code, <c>confirmation_required</c>.</param>
/// <param name="ErrorDescription">Human-readable text for diagnosis, not for the end user.</param>
/// <param name="Confirmation">The value to render into the page asking the end user, and to send back as the
/// <c>confirmation</c> parameter of the next request.</param>
public readonly record struct ConfirmationRequiredResponse(
	string Error,
	string ErrorDescription,
	string Confirmation)
{
	/// <inheritdoc cref="ErrorResponse.Error"/>
	[JsonPropertyName("error")]
	public string Error { get; init; } = Error;

	/// <inheritdoc cref="ErrorResponse.ErrorDescription"/>
	[JsonPropertyName("error_description")]
	public string ErrorDescription { get; init; } = ErrorDescription;

	/// <summary>
	/// The value this server issued for the session the question is about. It is good for one use and expires
	/// with <see cref="Common.Configuration.OidcOptions.LogoutConfirmationLifetime"/>.
	/// </summary>
	[JsonPropertyName("confirmation")]
	public string Confirmation { get; init; } = Confirmation;
}
