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
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.Features.Consents;

/// <summary>
/// A decorator for the <see cref="IUserConsentsProvider"/> that enforces the prompt for consent when required.
/// This class intercepts the consent retrieval process to inject mandatory consent prompts based on the authorization
/// request details.
/// </summary>
public class PromptConsentDecorator: IUserConsentsProvider
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PromptConsentDecorator"/> class, wrapping an existing consents'
    /// provider.
    /// </summary>
    /// <param name="inner">The inner-to -<see cref="IUserConsentsProvider"/> delegate calls to when no explicit
    /// prompting is necessary.</param>
    public PromptConsentDecorator(IUserConsentsProvider inner)
    {
        _inner = inner;
    }

    private readonly IUserConsentsProvider _inner;

    /// <summary>
    /// Retrieves user consents, injecting a mandatory prompt for consent if specified by the authorization request.
    /// </summary>
    /// <param name="request">The validated authorization request containing details that may require user interaction
    /// for consent.</param>
    /// <param name="authSession">The current authentication session that might affect how consents are handled.</param>
    /// <returns>A task that resolves to an instance of <see cref="UserConsents"/>, which will include any consents
    /// that are pending based on the authorization request parameters.</returns>
    public async Task<UserConsents> GetUserConsentsAsync(ValidAuthorizationRequest request, AuthSession authSession)
        => request.Model.Prompt switch
        {
            // If the 'consent' prompt is explicitly requested, force all scopes and resources to be pending consent.
            Prompts.Consent => new UserConsents { Pending = new(request.Scope, request.Resources) },

            // Otherwise, defer to the inner consents' provider.
            _ => await _inner.GetUserConsentsAsync(request, authSession),
        };
}
