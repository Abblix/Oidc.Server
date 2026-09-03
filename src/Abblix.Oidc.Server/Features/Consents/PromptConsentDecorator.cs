// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.Features.Consents;

/// <summary>
/// Honours the OIDC Core section 3.1.2.1 <c>prompt=consent</c> parameter by short-circuiting the wrapped
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
            Prompts.Consent => new UserConsents
            {
                Pending = new(request.Scope, request.Resources)
                {
                    AuthorizationDetails = request.AuthorizationDetails,
                },
            },
            _ => await inner.GetUserConsentsAsync(request, authSession),
        };
}
