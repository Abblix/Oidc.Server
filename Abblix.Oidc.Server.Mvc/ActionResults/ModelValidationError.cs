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
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace Abblix.Oidc.Server.Mvc.ActionResults;

/// <summary>
/// Maps a model-layer validation failure onto the OAuth <c>invalid_request</c> error. The few checks the
/// declarative validation attributes enforce at binding time (an out-of-range <c>prompt</c>,
/// <c>response_mode</c>, <c>display</c>, ...) thereby surface in the same
/// <c>{ "error": "invalid_request", "error_description": ... }</c> envelope as every other rejection on
/// these endpoints, rather than as the <c>[ApiController]</c> default
/// <see cref="Microsoft.AspNetCore.Mvc.ValidationProblemDetails"/> 400 that OAuth/OIDC clients do not
/// understand. The result is rendered through <see cref="ActionResultExtensions.Format(OidcError, int, string)"/>,
/// the single place that turns an <see cref="OidcError"/> into an HTTP response.
/// </summary>
internal static class ModelValidationError
{
	private const string FallbackDescription =
		"The request is missing a required parameter, includes an invalid parameter value, " +
		"includes a parameter more than once, or is otherwise malformed";

	/// <summary>
	/// Builds an <see cref="OidcError"/> carrying the <see cref="ErrorCodes.InvalidRequest"/> code from a flat
	/// sequence of validation messages. The input is a plain message sequence on purpose, so a different
	/// transport adapter can feed it the output of
	/// <see cref="Validator.TryValidateObject(object, ValidationContext, ICollection{ValidationResult}, bool)"/>
	/// and share one source of truth for "a malformed request becomes invalid_request".
	/// </summary>
	/// <param name="messages">The human-readable validation messages collected for the rejected request.</param>
	/// <returns>An <see cref="OidcError"/> describing the failure in OAuth terms.</returns>
	public static OidcError InvalidRequest(IEnumerable<string> messages)
	{
		var description = string.Join(' ', messages.Where(message => !string.IsNullOrWhiteSpace(message)));

		// error_description is optional per RFC 6749 §5.2, so an empty join means the caller had no concrete
		// message and the generic fallback stands in for it.
		return new OidcError(
			ErrorCodes.InvalidRequest,
			description.Length > 0 ? description : FallbackDescription);
	}

	/// <summary>
	/// Aggregates the messages held in <paramref name="modelState"/> after a failed <c>[ApiController]</c>
	/// model-binding pass and maps them through <see cref="InvalidRequest(IEnumerable{string})"/>.
	/// </summary>
	/// <param name="modelState">The model state populated by MVC when binding or validation failed.</param>
	/// <returns>An <see cref="OidcError"/> describing the failure in OAuth terms.</returns>
	public static OidcError InvalidRequest(ModelStateDictionary modelState)
		=> InvalidRequest(modelState.SelectMany(entry => entry.Value!.Errors.Select(error => error.ErrorMessage)));
}
