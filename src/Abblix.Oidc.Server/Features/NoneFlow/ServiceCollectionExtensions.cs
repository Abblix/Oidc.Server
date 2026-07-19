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

namespace Abblix.Oidc.Server.Features.NoneFlow;

/// <summary>
/// DI extensions that opt the host into the OAuth 2.0 <c>none</c> response type.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Enables the <c>none</c> response type (OAuth 2.0 Multiple Response Type Encoding Practices §4),
    /// which authorizes a request without returning any code or token — the authorization endpoint
    /// responds with only <c>state</c> and, when advertised, <c>iss</c> (RFC 9207).
    /// </summary>
    /// <remarks>
    /// By default this library does not register the <c>none</c> response-type processor, so the
    /// authorization endpoint rejects <c>response_type=none</c> with <c>unsupported_response_type</c>
    /// and the discovery document omits <c>none</c> from <c>response_types_supported</c>. Hosts that
    /// need it — for example, to pre-authorize a grant the client redeems later by other means — opt in
    /// via this method, mirroring the <c>EnableImplicitFlow</c> precedent for non-core response types. A
    /// client must additionally list <c>none</c> among its allowed response types to use it.
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to register the processor in.</param>
    /// <returns>The <see cref="IServiceCollection"/> so additional calls can be chained.</returns>
    public static IServiceCollection EnableNoneFlow(this IServiceCollection services)
    {
        // NoneResponseBuilder has no dependencies, so it stays a singleton (the default lifetime).
        services.AddAuthorizationResponseProcessor<NoneResponseBuilder>();
        return services;
    }
}
