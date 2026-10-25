// Abblix OIDC Client Library
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


namespace Abblix.Oidc.Client.Features.ClientAuthentication;

/// <summary>
/// Puts this client's credentials on a request to one of the provider's authenticated endpoints.
/// </summary>
/// <remarks>
/// One implementation serves every such endpoint. RFC 6749 section 2.3 defines client authentication once,
/// and the endpoints that need it refer back to that one definition: the token endpoint in section 3.2.1,
/// the revocation endpoint in RFC 7009 section 2.1. Reproducing the credential handling per endpoint is how
/// one of them ends up unauthenticated, or authenticated differently, without anyone deciding so.
/// </remarks>
public interface IClientCredentialsPresenter
{
    /// <summary>
    /// Applies the configured credentials to <paramref name="request"/>, adding form parameters to
    /// <paramref name="parameters"/> when the configured method carries the credentials in the body.
    /// </summary>
    /// <param name="request">The request being sent, whose headers may receive the credentials.</param>
    /// <param name="parameters">
    /// The form parameters of the request, which may receive the credentials instead. The caller encodes
    /// them into the body after this call, so entries added here reach the provider.
    /// </param>
    /// <exception cref="ClientAuthenticationException">
    /// The configured method is one this client cannot present, or needs a secret that is not configured.
    /// </exception>
    void Present(HttpRequestMessage request, IDictionary<string, string> parameters);
}
