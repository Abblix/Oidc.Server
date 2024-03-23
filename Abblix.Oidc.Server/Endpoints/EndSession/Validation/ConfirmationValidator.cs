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

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.EndSession.Validation;

/// <summary>
/// Represents a validator for end-session requests requiring user confirmation.
/// </summary>
public class ConfirmationValidator:  IEndSessionContextValidator
{
    /// <summary>
    /// Validates the end-session request for confirmation.
    /// </summary>
    /// <param name="context">The end-session validation context.</param>
    /// <returns>A task representing the asynchronous operation.
    /// The result is a validation error if confirmation is missing; otherwise, null.</returns>
    public Task<EndSessionRequestValidationError?> ValidateAsync(EndSessionValidationContext context)
        => Task.FromResult(Validate(context));

    private static EndSessionRequestValidationError? Validate(EndSessionValidationContext context)
    {
        var request = context.Request;

        if (!request.Confirmed && !request.IdTokenHint.HasValue())
        {
            return new EndSessionRequestValidationError(
                ErrorCodes.ConfirmationRequired,
                "The request requires to be confirmed by user");
        }

        return null;
    }
}
