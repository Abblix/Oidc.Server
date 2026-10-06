// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.Features.Consents;

/// <summary>
/// Honours the OIDC Core section 3.1.2.1 <c>prompt=consent</c> parameter over the wrapped
/// <see cref="IUserConsentsProvider"/>: until the end user gives consent on the page the server sent them to for
/// this request, every requested scope and resource is pending, so the consent page is shown even when the user
/// granted it before. A consent the host records as given since then, by <see cref="UserConsents.GivenAt"/>,
/// answers the prompt, and the request proceeds with the host's consents. A request not asking for consent gets the
/// host's consents unchanged.
/// </summary>
/// <param name="inner">The host's consents.</param>
public class PromptConsentDecorator(IUserConsentsProvider inner) : IUserConsentsProvider
{
    /// <summary>
    /// The host's consents, or every requested scope and resource as <see cref="UserConsents.Pending"/> while the
    /// request asks for consent and the end user has not given it on this request's consent page.
    /// </summary>
    /// <param name="request">The validated authorization request whose <c>prompt</c> parameter drives the decision.</param>
    /// <param name="authSession">The current authentication session forwarded to the inner provider.</param>
    public async Task<UserConsents> GetUserConsentsAsync(ValidAuthorizationRequest request, AuthSession authSession)
    {
        var consents = await inner.GetUserConsentsAsync(request, authSession);
        if (!PromptPages.Asks(request.Model, Prompts.Consent) ||
            PromptPages.AnsweredBy(request.Model, Prompts.Consent, consents.GivenAt))
        {
            return consents;
        }

        return new UserConsents
        {
            Pending = new(request.Scope, request.Resources)
            {
                AuthorizationDetails = request.AuthorizationDetails,
            },
        };
    }
}
