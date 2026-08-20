// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
