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
    private readonly ILogger _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="FlowTypeValidator" /> class with a logger.
    /// The logger is used for recording the validation activities, aiding in troubleshooting and auditing.
    /// </summary>
    /// <param name="logger">The logger to be used for logging purposes.</param>
    public FlowTypeValidator(ILogger<FlowTypeValidator> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Validates the flow type specified in the authorization request.
    /// This method checks if the flow type is supported and aligns with the OAuth 2.0 specifications.
    /// </summary>
    /// <param name="context">The validation context containing client and request information.</param>
    /// <returns>
    /// An <see cref="AuthorizationRequestValidationError" /> if the flow type is not valid or supported,
    /// or null if the flow type is valid.
    /// </returns>
    protected override AuthorizationRequestValidationError? Validate(AuthorizationValidationContext context)
    {
        var responseType = context.Request.ResponseType;

        if (!ResponseTypeAllowed(context))
        {
            _logger.LogWarning("The response type {@ResponseType} is not allowed for the client",
                [responseType]);
            return UnsupportedResponseType("The response type is not allowed for the client");
        }

        if (!TryDetectFlowType(responseType, out var flowType, out var responseMode))
        {
            _logger.LogWarning("The response type {@ResponseType} is not valid", [responseType]);
            return UnsupportedResponseType("The response type is not supported");
        }

        context.FlowType = flowType;
        context.ResponseMode = responseMode;
        return null;

        AuthorizationRequestValidationError UnsupportedResponseType(string message)
        {
            context.ResponseMode = context.Request.ResponseMode ?? ResponseModes.Query;

            return context.Error(
                ErrorCodes.UnsupportedResponseType,
                message);
        }
    }

    /// <summary>
    /// Validates whether the requested response type in an authorization request matches any of the allowed response
    /// types registered for the client. This ensures the client uses a valid and permitted OAuth/OpenID Connect flow.
    /// </summary>
    /// <param name="context">The authorization validation context containing the client and request details.</param>
    /// <returns>
    /// A boolean indicating whether the requested response type is allowed for the client.
    /// </returns>
    private static bool ResponseTypeAllowed(AuthorizationValidationContext context)
    {
        var responseType = context.Request.ResponseType;

        // If the response type is not specified, it means the request is invalid
        if (responseType == null)
            return false;

        // Convert the requested response type array into a hashset for faster lookup
        var responseTypeSet = responseType.ToHashSet(StringComparer.Ordinal);

        // Check if any of the allowed response types matches the requested response type
        return Array.Exists(
            context.ClientInfo.AllowedResponseTypes,
            allowedResponseType => responseTypeSet.Count == allowedResponseType.Length &&
                                   Array.TrueForAll(allowedResponseType, responseTypeSet.Contains));
    }

    /// <summary>
    /// Attempts to detect the OAuth 2.0 flow type based on the specified response types.
    /// </summary>
    /// <param name="responseType">An array of response types to examine.</param>
    /// <param name="flowType">The detected flow type, if successful.</param>
    /// <param name="responseMode">The default response mode for the detected flow type, if successful.</param>
    /// <returns>A boolean value indicating whether the detection was successful.</returns>
    private static bool TryDetectFlowType([NotNullWhen(true)] string[]? responseType, out FlowTypes flowType,
        out string responseMode)
    {
        var code = responseType.HasFlag(ResponseTypes.Code);
        var token = responseType.HasFlag(ResponseTypes.Token) || responseType.HasFlag(ResponseTypes.IdToken);

        (var result, flowType, responseMode) = (code, token) switch
        {
            (code: true, token: false) => (true, FlowTypes.AuthorizationCode, ResponseModes.Query),
            (code: false, token: true) => (true, FlowTypes.Implicit, ResponseModes.Fragment),
            (code: true, token: true) => (true, FlowTypes.Hybrid, ResponseModes.Fragment),
            _ => (false, default, default!)
        };

        return result;
    }
}
