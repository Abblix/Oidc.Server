// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server


using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using static Abblix.Oidc.Server.Model.AuthorizationRequest;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Refuses a <c>prompt</c> that combines <c>none</c> with another value: OpenID Connect Core 1.0, section 3.1.2.1,
/// "If this parameter contains none with any other value, an error is returned."
/// </summary>
/// <remarks>
/// Each value is one the server supports by the time this runs, since the request model refuses any other as it is
/// read. The combination is refused here rather than there, after the client and the redirect URI are validated, so the
/// client is told at its redirect URI instead of the end user's browser showing a 400.
/// </remarks>
public class PromptValidator : SyncAuthorizationContextValidatorBase
{
    /// <inheritdoc />
    protected override AuthorizationRequestValidationError? Validate(AuthorizationValidationContext context)
    {
        if (context.Request.Prompt is { } prompt &&
            prompt.Contains(Prompts.None, StringComparer.Ordinal) &&
            prompt.Any(value => value != Prompts.None))
        {
            return context.InvalidRequest(
                $"The {Parameters.Prompt} parameter combines {Prompts.None} with another value.");
        }

        return null;
    }
}
