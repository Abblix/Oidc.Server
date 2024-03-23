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

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.UriValidation;
using Microsoft.Extensions.Logging;



namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Validates the redirect URI specified in the authorization request.
/// This class checks whether the provided redirect URI matches one of the client's registered redirect URIs,
/// as part of the authorization validation process. It is essential for ensuring that redirections
/// only occur to pre-approved locations, enhancing security in the OAuth 2.0 flow.
/// </summary>
public class RedirectUriValidator : SyncAuthorizationContextValidatorBase
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RedirectUriValidator"/> class with a logger.
    /// The logger is used to record validation activities and outcomes, providing insights into
    /// the validation process and aiding in debugging and audit trails.
    /// </summary>
    /// <param name="logger">The logger to be used for logging validation process and outcomes.</param>
    public RedirectUriValidator(ILogger<RedirectUriValidator> logger)
    {
        _logger = logger;
    }

    private readonly ILogger _logger;

    /// <summary>
    /// Validates the redirect URI specified in the authorization request against the registered redirect URIs
    /// for the client. Ensures that the redirect URI is one of the pre-approved URIs for the client making the request.
    /// This validation is crucial for preventing unauthorized redirections in the OAuth 2.0 authorization flow.
    /// </summary>
    /// <param name="context">The validation context containing client information and the request details.</param>
    /// <returns>
    /// An <see cref="AuthorizationRequestValidationError"/> if the redirect URI is not valid for the specified client,
    /// or null if the redirect URI is valid.
    /// </returns>
    protected override AuthorizationRequestValidationError? Validate(AuthorizationValidationContext context)
    {
        var uriValidator = UriValidatorFactory.Create(context.ClientInfo.RedirectUris);

        var redirectUri = context.Request.RedirectUri;
        if (redirectUri == null || !uriValidator.IsValid(redirectUri))
        {
            _logger.LogWarning("The redirect URI {RedirectUri} is invalid for client with id {ClientId}",
                redirectUri,
                context.ClientInfo.ClientId);

            return context.InvalidRequest("The redirect URI is not valid for specified client");
        }

        context.ValidRedirectUri = redirectUri;

        return null;
    }
}
