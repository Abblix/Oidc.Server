// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
    /// OAuth 2.1 (draft) deprecates the Implicit Grant. By default this library does not register
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
        // TokenResponseBuilder depends only on the singleton IAccessTokenService, so it stays a
        // singleton. IdTokenResponseBuilder depends on the scoped IIdentityTokenService (which in
        // turn consumes the scoped IUserClaimsProvider), so it must be scoped to avoid a captive
        // dependency under host service-provider scope validation.
        services.AddAuthorizationResponseProcessor<TokenResponseBuilder>();
        services.AddAuthorizationResponseProcessor<IdTokenResponseBuilder>(ServiceLifetime.Scoped);
        return services;
    }
}
