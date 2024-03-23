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

using System.Net.Http.Headers;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using HttpRequestHeaders = Abblix.Oidc.Server.Common.Constants.HttpRequestHeaders;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Handles the validation of registration access tokens, ensuring they adhere to JWT standards and
/// are authorized for use by specific clients.
/// </summary>
public class RegistrationAccessTokenValidator : IRegistrationAccessTokenValidator
{
    /// <summary>
    /// Constructs a new instance of the <see cref="RegistrationAccessTokenValidator"/>, equipped with a JWT validation
    /// service for verifying the integrity and authorization of registration access tokens.
    /// </summary>
    /// <param name="jwtValidator">An implementation of <see cref="IAuthServiceJwtValidator"/> responsible for the
    /// JWT validation logic.</param>
    public RegistrationAccessTokenValidator(IAuthServiceJwtValidator jwtValidator)
    {
        _jwtValidator = jwtValidator;
    }

    private readonly IAuthServiceJwtValidator _jwtValidator;

    /// <summary>
    /// Asynchronously validates a registration access token, verifying its format, type, and authorization for
    /// the intended client.
    /// </summary>
    /// <param name="header">The HTTP Authorization header containing the bearer token to be validated.</param>
    /// <param name="clientId">The unique identifier of the client that the token is supposed to authorize.</param>
    /// <returns>
    /// A task that results in a nullable string; returns null if the token is valid and authorized for the specified
    /// client, or an error message detailing the reason for validation failure.
    /// </returns>
    /// <remarks>
    /// This method is crucial for securing client registration and management endpoints by ensuring that only valid
    /// and authorized registration access tokens can perform operations. It checks the token's type, audience
    /// and subject against the expected values, employing JWT validation to ascertain its integrity and applicability.
    /// </remarks>
    public async Task<string?> ValidateAsync(AuthenticationHeaderValue? header, string clientId)
    {
        if (header?.Parameter == null)
            return $"The access token must be specified via '{HttpRequestHeaders.Authorization}' header";

        if (header.Scheme != TokenTypes.Bearer)
            return $"The scheme name '{header.Scheme}' is not supported";

        var result = await _jwtValidator.ValidateAsync(
            header.Parameter,
            ValidationOptions.Default & ~ValidationOptions.ValidateAudience);

        switch (result)
        {
            case ValidJsonWebToken
            {
                Token:
                {
                    Header.Type: var tokenType,
                    Payload: { Audiences: var audiences, Subject: var subject },
                }
            }:
                if (tokenType != JwtTypes.RegistrationAccessToken)
                    return $"Invalid token type: {tokenType}";

                if (subject != clientId || !audiences.Contains(clientId))
                    return "The access token unauthorized";

                break;

            case JwtValidationError error:
                return error.ErrorDescription;

            default:
                throw new UnexpectedTypeException(nameof(result), result.GetType());
        }

        return default;
    }
}
