// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;
using Abblix.Oidc.Server.Endpoints.EndSession.Validation;
using Abblix.Oidc.Server.Model;


namespace Abblix.Oidc.Server.Endpoints.EndSession;

/// <summary>
/// Implements the logic for validating end-session requests.
/// </summary>
/// <param name="validator">The end-session context validator responsible for the core validation logic.</param>
/// <remarks>
/// This class validates end-session requests to ensure they conform to expected standards and business rules.
/// It uses the injected <see cref="IEndSessionContextValidator"/> for performing the actual validation logic.
/// Depending on the validation outcome, it constructs an appropriate validation result which can indicate either
/// successful validation or a specific error condition.
/// </remarks>
public class EndSessionRequestValidator(IEndSessionContextValidator validator) : IEndSessionRequestValidator
{
    /// <inheritdoc/>
    /// <summary>
    /// Validates the specified end-session request asynchronously.
    /// </summary>
    /// <param name="request">The end-session request to be validated.</param>
    /// <returns>
    /// A task representing the asynchronous validation operation. The task result contains the
    /// <see cref="Result{ValidEndSessionRequest, AuthError}"/> which encapsulates the validation outcome.
    /// </returns>
    public async Task<Result<ValidEndSessionRequest, OidcError>> ValidateAsync(EndSessionRequest request)
    {
        var context = new EndSessionValidationContext(request);

        var error = await validator.ValidateAsync(context);
        if (error != null)
            return error;

        return new ValidEndSessionRequest(context.Request, context.ClientInfo);
    }
}
