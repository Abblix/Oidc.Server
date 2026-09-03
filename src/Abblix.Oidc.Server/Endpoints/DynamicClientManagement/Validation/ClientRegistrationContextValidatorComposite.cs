// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Composite that runs the configured chain of <see cref="IClientRegistrationContextValidator"/>
/// steps in order and short-circuits on the first failure, mirroring RFC 7591 section 3.2.2 which
/// requires the server to reject a registration on the first invalid metadata field.
/// </summary>
/// <param name="validationSteps">The validation steps to execute, in order.</param>
public class ClientRegistrationContextValidatorComposite(IClientRegistrationContextValidator[] validationSteps) : IClientRegistrationContextValidator
{
    /// <summary>
    /// Runs each step until one returns an error or all succeed.
    /// </summary>
    /// <param name="context">The shared validation context.</param>
    /// <returns>The first error produced, or <c>null</c> when every step passes.</returns>
    public Task<OidcError?> ValidateAsync(ClientRegistrationValidationContext context)
        => validationSteps.FirstOrDefaultAsync(v => v.ValidateAsync(context));
}
