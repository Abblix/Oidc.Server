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

using Abblix.Oidc.Server.Endpoints;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Features.ImplicitFlow;

/// <summary>
/// DI extensions that opt the host into the OAuth 2.0 / OIDC Implicit and Hybrid Flows.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Enables support for the Implicit and Hybrid Flows by registering the response-type
    /// processors that emit access tokens and ID tokens directly from the authorization endpoint.
    /// </summary>
    /// <remarks>
    /// OAuth 2.1 §1.4 deprecates the Implicit Grant. By default this library does not register
    /// the <c>token</c> or <c>id_token</c> response-type processors, so the authorization endpoint
    /// rejects requests for those response types with <c>unsupported_response_type</c> and the
    /// discovery document advertises only <c>code</c> in <c>response_types_supported</c> and
    /// omits <c>implicit</c> from <c>grant_types_supported</c>. Hosts that still need Implicit
    /// or Hybrid (legacy SPAs, transition deployments) make a deliberate decision to opt in via
    /// this method, mirroring the <c>EnablePasswordGrant</c> precedent for ROPC.
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to register the Implicit /
    /// Hybrid response-type processors in.</param>
    /// <returns>The <see cref="IServiceCollection"/> so additional calls can be chained.</returns>
    public static IServiceCollection EnableImplicitFlow(this IServiceCollection services)
    {
        services.AddAuthorizationResponseProcessor<TokenResponseBuilder>();
        services.AddAuthorizationResponseProcessor<IdTokenResponseBuilder>();
        return services;
    }
}
