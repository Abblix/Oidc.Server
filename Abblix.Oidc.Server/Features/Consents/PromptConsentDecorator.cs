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
/// Honours the OIDC Core §3.1.2.1 <c>prompt=consent</c> parameter by short-circuiting the wrapped
/// <see cref="IUserConsentsProvider"/>: when the client explicitly requests consent re-confirmation,
/// every requested scope and resource is forced into the pending bucket so the consent UI is shown
/// even if the user previously granted it. For any other prompt value the decorator delegates to the
/// inner provider unchanged.
/// </summary>
/// <param name="inner">The wrapped consent provider used when <c>prompt=consent</c> is not requested.</param>
public class PromptConsentDecorator(IUserConsentsProvider inner) : IUserConsentsProvider
{
    /// <summary>
    /// If the authorization request carries <c>prompt=consent</c>, returns all requested scopes and
    /// resources as <see cref="UserConsents.Pending"/> to force a fresh consent prompt; otherwise
    /// delegates to the wrapped provider.
    /// </summary>
    /// <param name="request">The validated authorization request whose <c>prompt</c> parameter drives the decision.</param>
    /// <param name="authSession">The current authentication session forwarded to the inner provider.</param>
    public async Task<UserConsents> GetUserConsentsAsync(ValidAuthorizationRequest request, AuthSession authSession)
        => request.Model.Prompt switch
        {
            Prompts.Consent => new UserConsents { Pending = new(request.Scope, request.Resources) },
            _ => await inner.GetUserConsentsAsync(request, authSession),
        };
}
