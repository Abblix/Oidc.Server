// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
