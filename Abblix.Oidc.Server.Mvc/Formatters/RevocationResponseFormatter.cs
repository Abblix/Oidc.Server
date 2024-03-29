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

using Abblix.Oidc.Server.Endpoints.Revocation.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.Formatters;

/// <summary>
/// Formatter for responses to token revocation requests.
/// </summary>
public class RevocationResponseFormatter : IRevocationResponseFormatter
{
    /// <summary>
    /// Asynchronously formats the response for a token revocation request.
    /// </summary>
    /// <remarks>
    /// This method handles different types of revocation responses and formats them
    /// into appropriate HTTP action results.
    /// </remarks>
    /// <param name="request">The token revocation request.</param>
    /// <param name="response">The response to the token revocation request.</param>
    /// <returns>
    /// A task that represents the asynchronous operation. The task result contains the formatted action result.
    /// </returns>
    public Task<ActionResult> FormatResponseAsync(RevocationRequest request, RevocationResponse response)
    {
        return Task.FromResult<ActionResult>(response switch
        {
            TokenRevokedResponse => new OkResult(),
            RevocationErrorResponse error => new BadRequestObjectResult(new ErrorResponse(error.Error,
                error.ErrorDescription)),
            _ => throw new ArgumentOutOfRangeException(nameof(response))
        });
    }
}
