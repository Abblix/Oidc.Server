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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.EndSession.Validation;

/// <summary>
/// Enforces the end-user confirmation step described in OpenID Connect RP-Initiated Logout 1.0 §2:
/// when the request omits <c>id_token_hint</c> the OP cannot trust that the user really
/// initiated the logout, so a UI confirmation must precede the call. This validator surfaces
/// <see cref="ErrorCodes.ConfirmationRequired"/> until the host echoes back
/// <c>confirmed=true</c>.
/// </summary>
public class ConfirmationValidator:  IEndSessionContextValidator
{
    /// <inheritdoc />
    public Task<OidcError?> ValidateAsync(EndSessionValidationContext context)
        => Task.FromResult(Validate(context));

    private static OidcError? Validate(EndSessionValidationContext context)
    {
        var request = context.Request;

        if (request.Confirmed != true && !request.IdTokenHint.HasValue())
        {
            return new OidcError(
                ErrorCodes.ConfirmationRequired,
                "The request requires to be confirmed by user");
        }

        return null;
    }
}
