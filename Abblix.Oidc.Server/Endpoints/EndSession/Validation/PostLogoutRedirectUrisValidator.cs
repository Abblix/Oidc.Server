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
using Abblix.Oidc.Server.Features.UriValidation;
using Microsoft.Extensions.Logging;
using static Abblix.Oidc.Server.Model.EndSessionRequest;

namespace Abblix.Oidc.Server.Endpoints.EndSession.Validation;

/// <summary>
/// Validates the post-logout redirect URIs for an end-session request.
/// </summary>
public class PostLogoutRedirectUrisValidator : IEndSessionContextValidator
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PostLogoutRedirectUrisValidator"/> class.
    /// </summary>
    /// <param name="logger">The logger for capturing validation information.</param>
    public PostLogoutRedirectUrisValidator(ILogger<PostLogoutRedirectUrisValidator> logger)
    {
        _logger = logger;
    }

    private readonly ILogger _logger;

    /// <summary>
    /// Validates the end-session request asynchronously.
    /// </summary>
    /// <param name="context">The end-session validation context.</param>
    /// <returns>
    /// A task that represents the asynchronous validation operation.
    /// Returns an EndSessionRequestValidationError if validation fails, or null if successful.
    /// </returns>
    public Task<EndSessionRequestValidationError?> ValidateAsync(EndSessionValidationContext context)
        => Task.FromResult(Validate(context));

    private EndSessionRequestValidationError? Validate(EndSessionValidationContext context)
    {
        var request = context.Request;

        var redirectUri = request.PostLogoutRedirectUri;
        if (redirectUri == null)
            return null;

        if (context.ClientInfo == null)
        {
             return new EndSessionRequestValidationError(
                 ErrorCodes.UnauthorizedClient,
                 $"Unable to determine a client from {Parameters.ClientId} or {Parameters.IdTokenHint}, but it is necessary to validate {Parameters.PostLogoutRedirectUri} value");
        }

        var uriValidator = UriValidatorFactory.Create(context.ClientInfo.PostLogoutRedirectUris);
        if (uriValidator.IsValid(redirectUri))
            return null;

        _logger.LogWarning("The post-logout redirect URI {RedirectUri} is invalid for client with id {ClientId}",
            redirectUri,
            context.ClientInfo.ClientId);

        return new EndSessionRequestValidationError(
            ErrorCodes.InvalidRequest,
            "The post-logout redirect URI is not valid for specified client");
    }
}
