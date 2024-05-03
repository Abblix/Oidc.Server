﻿// Abblix OIDC Server Library
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

using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;
using Abblix.Oidc.Server.Endpoints.EndSession.Validation;
using Abblix.Oidc.Server.Model;


namespace Abblix.Oidc.Server.Endpoints.EndSession;

/// <summary>
/// Implements the logic for validating end-session requests.
/// </summary>
/// <remarks>
/// This class validates end-session requests to ensure they conform to expected standards and business rules.
/// It uses the injected <see cref="IEndSessionContextValidator"/> for performing the actual validation logic.
/// Depending on the validation outcome, it constructs an appropriate validation result which can indicate either
/// successful validation or a specific error condition.
/// </remarks>
public class EndSessionRequestValidator : IEndSessionRequestValidator
{
    /// <summary>
    /// Initializes a new instance of the <see cref="EndSessionRequestValidator"/> class.
    /// </summary>
    /// <param name="validator">The end-session context validator responsible for the core validation logic.</param>
    public EndSessionRequestValidator(IEndSessionContextValidator validator)
    {
        _validator = validator;
    }

    private readonly IEndSessionContextValidator _validator;

    /// <inheritdoc/>
    /// <summary>
    /// Validates the specified end-session request asynchronously.
    /// </summary>
    /// <param name="request">The end-session request to be validated.</param>
    /// <returns>
    /// A task representing the asynchronous validation operation. The task result contains the
    /// <see cref="EndSessionRequestValidationResult"/> which encapsulates the validation outcome.
    /// </returns>
    public async Task<EndSessionRequestValidationResult> ValidateAsync(EndSessionRequest request)
    {
        var context = new EndSessionValidationContext(request);

        var result = await _validator.ValidateAsync(context) ??
                     (EndSessionRequestValidationResult)new ValidEndSessionRequest(context.Request, context.ClientInfo);

        return result;
    }
}
