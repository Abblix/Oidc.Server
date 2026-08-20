// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Token.Validation;

/// <summary>
/// Represents a composite validator for token context validation, executing a sequence of individual validators.
/// This class allows multiple validators to be combined, each responsible for a specific validation step,
/// and short-circuits the validation process if any step fails.
/// </summary>
/// <param name="validators">An array of validators representing the steps in the validation process.</param>
public class TokenContextValidatorComposite(ITokenContextValidator[] validators) : ITokenContextValidator
{
    /// <summary>
    /// Asynchronously validates the token request by executing each validator in the sequence.
    /// The validation process stops at the first encountered error and returns it.
    /// If all validators succeed, the method returns null, indicating successful validation.
    /// </summary>
    /// <param name="context">The context containing the token request and related information
    /// that needs to be validated.</param>
    /// <returns>
    /// A <see cref="OidcError"/> containing error details if any validation step fails;
    /// otherwise, returns null indicating that all validation steps were successful.
    /// </returns>
    /// <param name="cancellationToken">Abandons the operation when the caller stops waiting.</param>
    public Task<OidcError?> ValidateAsync(TokenValidationContext context, CancellationToken cancellationToken)
        => validators.FirstOrDefaultAsync(v => v.ValidateAsync(context, cancellationToken));
}
