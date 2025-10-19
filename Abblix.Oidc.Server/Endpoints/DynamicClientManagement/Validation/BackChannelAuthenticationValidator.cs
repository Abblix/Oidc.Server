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

using Abblix.Oidc.Server.Common;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Validates backchannel authentication configurations during client registration.
/// This class ensures that the backchannel token delivery mode and notification endpoint
/// meet the requirements of the CIBA (Client-Initiated Backchannel Authentication) protocol.
/// Additionally, it checks for the presence of supported signing algorithms.
/// </summary>
public class BackChannelAuthenticationValidator: IClientRegistrationContextValidator
{
    /// <summary>
    /// Initializes the validator with the necessary components, including a JWT validator
    /// to verify supported signing algorithms.
    /// </summary>
    /// <param name="jwtValidator">The service responsible for validating JWT signing algorithms.</param>
    public BackChannelAuthenticationValidator(IJsonWebTokenValidator jwtValidator)
    {
        _jwtValidator = jwtValidator;
    }

    private readonly IJsonWebTokenValidator _jwtValidator;

    /// <summary>
    /// Asynchronously validates the client registration context, returning any errors found during validation.
    /// </summary>
    /// <param name="context">The context containing the client registration request.</param>
    /// <returns>A task that represents the result of the validation, either an error or null if valid.</returns>
    public Task<RequestError?> ValidateAsync(ClientRegistrationValidationContext context)
        => Task.FromResult(Validate(context));

    /// <summary>
    /// Validates the backchannel token delivery mode, notification endpoints, and signing algorithms specified
    /// in the client registration request.
    /// </summary>
    /// <param name="context">The context containing the client registration request.</param>
    /// <returns>A validation error if the request is invalid, or null if the request is valid.</returns>
    private RequestError? Validate(ClientRegistrationValidationContext context)
    {
        switch (context.Request)
        {
            // If the backchannel token delivery mode is not set, assume CIBA is not enabled for the client
            case { BackChannelTokenDeliveryMode: null }:
                return null;

            // If delivery mode is set to "poll" but a notification endpoint is provided, return an error
            case {
                BackChannelTokenDeliveryMode: BackchannelTokenDeliveryModes.Poll,
                BackChannelClientNotificationEndpoint: not null,
            }:
                return new RequestError(
                    ErrorCodes.InvalidRequest,
                    "Notification endpoint is invalid if the token delivery mode is set to poll");

            // If delivery mode is set to "ping" or "push" but no notification endpoint is provided, return an error
            case {
                BackChannelTokenDeliveryMode: BackchannelTokenDeliveryModes.Ping or BackchannelTokenDeliveryModes.Push,
                BackChannelClientNotificationEndpoint: null,
            }:
                return new RequestError(
                    ErrorCodes.InvalidRequest,
                    "Notification endpoint is required if the token delivery mode is set to ping or push");

            // Valid configurations for poll, ping, and push modes
            case { BackChannelTokenDeliveryMode: BackchannelTokenDeliveryModes.Poll }:
            //case { BackChannelTokenDeliveryMode: BackchannelTokenDeliveryModes.Ping or BackchannelTokenDeliveryModes.Push }:
                break;

            // If the token delivery mode is not supported, return an error
            default:
                return new RequestError(
                    ErrorCodes.InvalidRequest,
                    "The specified token delivery mode is not supported");
        }

        // Check if the signing algorithm specified in the request is supported
        var signingAlgorithm = context.Request.BackChannelAuthenticationRequestSigningAlg;
        if (signingAlgorithm.HasValue() &&
            !_jwtValidator.SigningAlgorithmsSupported.Contains(signingAlgorithm, StringComparer.Ordinal))
        {
            return new RequestError(
                ErrorCodes.InvalidRequest,
                "The specified signing algorithm is not supported");
        }

        // If all validations pass, return null indicating the request is valid
        return null;
    }
}
