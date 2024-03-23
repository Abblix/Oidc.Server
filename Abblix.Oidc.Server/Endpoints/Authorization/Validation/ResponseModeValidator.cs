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

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Utils;
using Microsoft.Extensions.Logging;



namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// This class is responsible for validating the response mode specified in the authorization request
/// as part of the SyncAuthorizationRequestValidationStep process.
/// </summary>
public class ResponseModeValidator : SyncAuthorizationContextValidatorBase
{
	/// <summary>
	/// Initializes a new instance of the ResponseModeValidator class with a logger.
	/// </summary>
	/// <param name="logger">The logger to be used for logging purposes.</param>
	public ResponseModeValidator(ILogger<ResponseModeValidator> logger)
	{
		_logger = logger;
	}

	private readonly ILogger _logger;

	/// <summary>
	/// Validates the response mode specified in the authorization request against the allowed
	/// response modes for the detected flow type.
	/// </summary>
	/// <param name="context">The validation context containing client information.</param>
	/// <returns>An AuthorizationRequestValidationError if the validation fails, or null if the request is valid.</returns>
	protected override AuthorizationRequestValidationError? Validate(AuthorizationValidationContext context)
	{
		var responseMode = context.Request.ResponseMode;
		if (responseMode.HasValue())
		{
			if (!IsResponseModeAllowed(responseMode, context.FlowType))
			{
				_logger.LogWarning("The response mode {ResponseMode} is not compatible with response type {ResponseType}",
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
