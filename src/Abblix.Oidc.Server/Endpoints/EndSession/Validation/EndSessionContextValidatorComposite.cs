// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.EndSession.Validation;

/// <summary>
/// Represents a composite validator for end-session requests.
/// </summary>
/// <param name="validationSteps">The array of end-session context validators to execute.</param>
public class EndSessionContextValidatorComposite(IEndSessionContextValidator[] validationSteps) : IEndSessionContextValidator
{
    /// <summary>
    /// Validates the end-session request using a composite of multiple validators.
    /// </summary>
    /// <param name="context">The end-session validation context.</param>
    /// <returns>A task representing the asynchronous operation.
    /// The result is a validation error if any validation step fails; otherwise, null.</returns>
    public Task<OidcError?> ValidateAsync(EndSessionValidationContext context)
        => validationSteps.FirstOrDefaultAsync(v => v.ValidateAsync(context));
}
