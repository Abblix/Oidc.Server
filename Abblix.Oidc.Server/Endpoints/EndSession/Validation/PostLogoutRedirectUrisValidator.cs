// Abblix OIDC Server Library
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

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;
using Abblix.Oidc.Server.Features.UriValidation;
using Abblix.Utils;
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
            new Sanitized(redirectUri),
            context.ClientInfo.ClientId);

        return new EndSessionRequestValidationError(
            ErrorCodes.InvalidRequest,
            "The post-logout redirect URI is not valid for specified client");
    }
}
