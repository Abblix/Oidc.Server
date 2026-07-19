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

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Enforces the RFC 9101 §10.5 <c>require_signed_request_object</c> client metadata: a client that
/// committed to it must deliver its authorization parameters as a signed request object. A request
/// that came neither from a request object nor from a PAR-stored request is plain parameters and is
/// rejected. The PAR push itself runs through the same validator pipeline, so a flagged client
/// cannot smuggle plain parameters in via PAR either; the signature itself (rejecting the
/// <c>none</c> algorithm) is enforced by the request-object fetcher where the JWT is validated.
/// </summary>
public class SignedRequestObjectRequirementValidator : SyncAuthorizationContextValidatorBase
{
    /// <inheritdoc />
    protected override AuthorizationRequestValidationError? Validate(AuthorizationValidationContext context)
    {
        if (context.ClientInfo.RequireSignedRequestObject &&
            context.Request is { Request: null, PushedRequestUri: null })
        {
            return context.InvalidRequest(
                "The client is required to pass authorization request parameters as a signed request object");
        }

        return null;
    }
}
