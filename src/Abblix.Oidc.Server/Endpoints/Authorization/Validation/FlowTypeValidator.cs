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
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Validates the OAuth 2.0 flow type specified in the authorization request.
/// This class determines if the requested flow type is supported and matches the
/// expected patterns for authorization requests, as part of the validation process.
/// </summary>
/// <param name="logger">The logger to be used for logging purposes.</param>
/// <param name="processors">The set of registered authorization response processors. The
/// validator rejects requests whose <c>response_type</c> contains a part with no matching
/// registered processor - this enforces OAuth 2.1 (draft) default-off Implicit Flow at the validation
/// layer (without <c>EnableImplicitFlow()</c>, no <c>token</c> / <c>id_token</c> processors exist
/// and any request asking for them gets <c>unsupported_response_type</c>).</param>
/// <param name="options">Provides the server-wide default security profile a client inherits when it
/// states none, used to reject implicit and hybrid response types for a client held to a code-only
/// profile (FAPI 2.0).</param>
public partial class FlowTypeValidator(
    ILogger<FlowTypeValidator> logger,
    IEnumerable<IAuthorizationResponseBuilder> processors,
    IOptions<OidcOptions> options) : SyncAuthorizationContextValidatorBase
{
    private readonly IReadOnlySet<string> _supportedResponseTypeParts =
        processors.Select(b => b.ResponseType).ToHashSet(StringComparer.Ordinal);

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
        var returnsTokenFromAuthorization = responseType.ReturnsTokenFromAuthorization();

        // RFC 6749 §4.1.2.1: response_type is REQUIRED, and a missing required parameter is
        // invalid_request - not unsupported_response_type (no method was named at all) and not
        // unauthorized_client (no client policy was consulted).
        if (responseType is not { Length: > 0 })
        {
            LogResponseTypeInvalid(responseType);
            return Error(ErrorCodes.InvalidRequest, "The response type is required");
        }

        // A code-only profile (FAPI 2.0) rejects any response type that returns a token or id_token
        // from the authorization endpoint, regardless of what the client's AllowedResponseTypes
        // permits - the profile tightens, the granular whitelist cannot widen it. Checked before the
        // server-support gate so a profiled client gets the profile-specific reason even on a server
        // where Implicit Flow is enabled for other clients.
        var profile = SecurityProfileRequirements.For(context.ClientInfo, options.Value.DefaultSecurityProfile);
        if (profile.RequireCodeResponseTypeOnly && returnsTokenFromAuthorization)
        {
            LogResponseTypeNotAllowed(responseType);
            return Error(
                ErrorCodes.UnauthorizedClient,
                "The security profile permits only the authorization code response type");
        }

        // Server-level support: every part of response_type must have a registered processor. This
        // is the gate that turns Implicit Flow opt-in: when EnableImplicitFlow() is not called,
        // the token / id_token processors are absent from DI and the corresponding parts get
        // rejected here regardless of client-level AllowedResponseTypes configuration.
        var unsupportedPart = responseType.FirstOrDefault(part => !_supportedResponseTypeParts.Contains(part));
        if (unsupportedPart != null)
        {
            LogResponseTypePartUnsupported(unsupportedPart);
            return Error(
                ErrorCodes.UnsupportedResponseType,
                $"The response type '{unsupportedPart}' is not supported by this server");
        }

        if (!ResponseTypeAllowed(context))
        {
            LogResponseTypeNotAllowed(responseType);
            // RFC 6749 §4.1.2.1 / §4.2.2.1: the server supports this response_type (the gate above
            // passed), but this particular client is not registered to use it - that is
            // unauthorized_client. unsupported_response_type (returned before) is reserved for
            // methods the server itself cannot produce.
            return Error(ErrorCodes.UnauthorizedClient, "The response type is not allowed for the client");
        }

        if (!TryDetectFlowType(responseType, out var flowType, out var responseMode))
        {
            LogResponseTypeInvalid(responseType);
            return Error(ErrorCodes.UnsupportedResponseType, "The response type is not supported");
        }

        context.FlowType = flowType;
        context.ResponseMode = responseMode;
        return null;

        AuthorizationRequestValidationError Error(string errorCode, string message)
        {
            context.ResponseMode = context.Request.ResponseMode ?? GetDefaultResponseMode();
            return context.Error(errorCode, message);
        }

        // OAuth 2.0 Multiple Response Types §5: when the requested response_type contains a
        // value that requires fragment encoding (token / id_token), the error response MUST be
        // returned in the fragment as well. The previous unconditional query default delivered
        // the error to a channel the client never reads and exposed it to the server hosting
        // the redirect URI via the query string.
        string GetDefaultResponseMode()
            => returnsTokenFromAuthorization ? ResponseModes.Fragment : ResponseModes.Query;
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
            context.ClientInfo.EffectiveResponseTypes,
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
    private static bool TryDetectFlowType(
        [NotNullWhen(true)] string[]? responseType,
        out FlowTypes flowType,
        [NotNullWhen(true)] out string? responseMode)
    {
        var none = responseType.HasFlag(ResponseTypes.None);
        var code = responseType.HasFlag(ResponseTypes.Code);
        var token = responseType.ReturnsTokenFromAuthorization();

        // OAuth 2.0 Multiple Response Type Encoding Practices section 4 says the `none` response type
        // "SHOULD NOT be combined with other Response Types". We reject the combination outright rather
        // than merely discouraging it: a none+anything request matches no case below, so detection fails
        // and the caller returns unsupported_response_type. That is our choice, stricter than the text.
        // The none flow defaults to the query response mode and carries no credentials.
        (var result, flowType, responseMode) = (none, code, token) switch
        {
            (none: true, code: false, token: false) => (true, FlowTypes.None, ResponseModes.Query),
            (none: false, code: true, token: false) => (true, FlowTypes.AuthorizationCode, ResponseModes.Query),
            (none: false, code: false, token: true) => (true, FlowTypes.Implicit, ResponseModes.Fragment),
            (none: false, code: true, token: true) => (true, FlowTypes.Hybrid, ResponseModes.Fragment),
            _ => (false, default, null)
        };

        // The postcondition is returned rather than asserted: the default arm above leaves the mode unset,
        // and returning the test itself means no arm added later can claim success while leaving it so.
        // The annotation alone would not catch that - Roslyn verifies a [NotNullWhen] postcondition on an
        // out parameter, but only against what the method actually returns.
        return result && responseMode is not null;
    }
}
