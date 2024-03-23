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

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

using Microsoft.Extensions.Logging;



namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Validates the OAuth 2.0 flow type specified in the authorization request.
/// This class determines if the requested flow type is supported and matches the
/// expected patterns for authorization requests, as part of the validation process.
/// </summary>
public class FlowTypeValidator : SyncAuthorizationContextValidatorBase
{
    /// <summary>
    /// Initializes a new instance of the <see cref="FlowTypeValidator"/> class with a logger.
    /// The logger is used for recording the validation activities, aiding in troubleshooting and auditing.
    /// </summary>
    /// <param name="logger">The logger to be used for logging purposes.</param>
    public FlowTypeValidator(ILogger<FlowTypeValidator> logger)
    {
        _logger = logger;
    }

    private readonly ILogger _logger;

    /// <summary>
    /// Validates the flow type specified in the authorization request.
    /// This method checks if the flow type is supported and aligns with the OAuth 2.0 specifications.
    /// </summary>
    /// <param name="context">The validation context containing client and request information.</param>
    /// <returns>
    /// An <see cref="AuthorizationRequestValidationError"/> if the flow type is not valid or supported,
    /// or null if the flow type is valid.
    /// </returns>
    protected override AuthorizationRequestValidationError? Validate(AuthorizationValidationContext context)
    {
        var responseType = context.Request.ResponseType;
        if (!TryDetectFlowType(responseType, out var flowType, out var responseMode))
        {
            _logger.LogWarning("The response type {@ResponseType} is not valid", new object?[] { responseType });

            context.ResponseMode = context.Request.ResponseMode ?? ResponseModes.Query;

            return context.Error(
                ErrorCodes.UnsupportedResponseType,
                "The response type is not supported");
        }

        context.FlowType = flowType;
        context.ResponseMode = responseMode;
        return null;
    }

    /// <summary>
    /// Attempts to detect the OAuth 2.0 flow type based on the specified response types.
    /// </summary>
    /// <param name="responseType">An array of response types to examine.</param>
    /// <param name="flowType">The detected flow type, if successful.</param>
    /// <param name="responseMode">The default response mode for the detected flow type, if successful.</param>
    /// <returns>A boolean value indicating whether the detection was successful.</returns>
	private static bool TryDetectFlowType([NotNullWhen(true)] string[]? responseType, out FlowTypes flowType, out string responseMode)
	{
		var code = responseType.HasFlag(ResponseTypes.Code);
		var token = responseType.HasFlag(ResponseTypes.Token) || responseType.HasFlag(ResponseTypes.IdToken);

		(var result, flowType, responseMode) = (code, token) switch
		{
			(code: true, token: false) => (true, FlowTypes.AuthorizationCode, ResponseModes.Query),
			(code: false, token: true) => (true, FlowTypes.Implicit, ResponseModes.Fragment),
			(code: true, token: true) => (true, FlowTypes.Hybrid, ResponseModes.Fragment),
			_ => (false, default, default!),
		};

		return result;
	}
}
