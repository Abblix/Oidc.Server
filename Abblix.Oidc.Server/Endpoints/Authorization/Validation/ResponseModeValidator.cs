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

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Utils;
using Microsoft.Extensions.Logging;



namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Verifies that an explicit <c>response_mode</c> is compatible with the OAuth 2.0 flow
/// derived from <c>response_type</c> (OAuth 2.0 Multiple Response Types §2.1, OAuth 2.0
/// Form Post Response Mode). For the authorization-code flow any of <c>query</c>,
/// <c>fragment</c>, <c>form_post</c> is allowed; flows that issue tokens at the
/// authorization endpoint (implicit, hybrid) refuse <c>query</c> because credentials
/// must not appear in the URL query string.
/// </summary>
public class ResponseModeValidator(ILogger<ResponseModeValidator> logger) : SyncAuthorizationContextValidatorBase
{
	/// <inheritdoc />
	protected override AuthorizationRequestValidationError? Validate(AuthorizationValidationContext context)
	{
		var responseMode = context.Request.ResponseMode;
		if (responseMode.HasValue())
		{
			if (!IsResponseModeAllowed(responseMode, context.FlowType))
			{
				logger.LogWarning("The response mode {ResponseMode} is not compatible with response type {ResponseType}",
					responseMode,
					context.Request.ResponseType);

				return context.InvalidRequest("The response mode is not supported");
			}

			context.ResponseMode = responseMode;
		}

		return null;
	}

	/// <summary>
	/// Determines if the specified response mode is allowed for the given flow type.
	/// </summary>
	/// <param name="responseMode">The response mode to validate.</param>
	/// <param name="flowType">The flow type associated with the authorization request.</param>
	/// <returns>A boolean value indicating whether the response mode is allowed for the specified flow type.</returns>
	private static bool IsResponseModeAllowed(string responseMode, FlowTypes flowType) => flowType switch
	{
		FlowTypes.AuthorizationCode => responseMode is ResponseModes.Query or ResponseModes.FormPost or ResponseModes.Fragment,
		FlowTypes.Implicit or FlowTypes.Hybrid => responseMode is ResponseModes.FormPost or ResponseModes.Fragment,
		_ => throw new UnexpectedTypeException(nameof(flowType), flowType.GetType()),
	};
}
