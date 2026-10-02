// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Server.Endpoints;

/// <summary>
/// Registers the validation pipeline every authorization request passes through.
/// </summary>
public static class AuthorizationValidationServiceCollectionExtensions
{
    /// <summary>
    /// Adds a series of validators for authorization context as a composite service to ensure comprehensive validation
    /// of authorization requests.
    /// </summary>
    /// <remarks>
    /// This method composes a pipeline of validators for various aspects of the authorization context,
    /// such as request object validation, client validation, and more.
    /// This composite validator approach enables modular and extensible validation logic, ensuring that
    /// authorization requests meet all necessary criteria and standards.
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddAuthorizationContextValidators(this IServiceCollection services)
    {
        // compose AuthorizationContext validation as a pipeline of several IAuthorizationContextValidator
        services.TryAddEnumerable([
            ServiceDescriptor.Singleton<IAuthorizationContextValidator, Authorization.Validation.ClientValidator>(),
            // Right after ClientValidator: needs the resolved ClientInfo and must reject plain
            // parameters from a require_signed_request_object client before further processing.
            ServiceDescriptor.Singleton<IAuthorizationContextValidator, SignedRequestObjectRequirementValidator>(),
            ServiceDescriptor.Singleton<IAuthorizationContextValidator, RedirectUriValidator>(),
            // Scoped: FlowTypeValidator consumes IEnumerable<IAuthorizationResponseBuilder>, which
            // includes the scoped IdTokenResponseBuilder once EnableImplicitFlow() is called.
            ServiceDescriptor.Scoped<IAuthorizationContextValidator, FlowTypeValidator>(),
            ServiceDescriptor.Singleton<IAuthorizationContextValidator, ResponseModeValidator>(),
            // After RedirectUriValidator and ResponseModeValidator, not merely after ClientValidator, even
            // though ClientInfo is what it reads. Its refusals are the kind RFC 6749 Section 4.1.2.1 says the
            // client must be told about, and the two validators above are what decide where a refusal goes and
            // in which channel: before them ValidRedirectUri is null and the client gets a 400 in the end
            // user's browser instead of a redirect carrying error and state. Placing it here also keeps
            // signature verification behind the cheap parameter checks rather than in front of them.
            ServiceDescriptor.Singleton<IAuthorizationContextValidator, Authorization.Validation.IdTokenHintValidator>(),
            // Beside the hint validator because it answers the same question by the other parameter the
            // specification names for it, and it inherits the placement reasoning above for the same reason.
            ServiceDescriptor.Singleton<IAuthorizationContextValidator,
                Authorization.Validation.RequestedSubjectValidator>(),
            // And beside both, because section 5.5.1.1 reads the same parameter for the other claim whose
            // description imposes a condition, and a refusal over it travels the same way.
            ServiceDescriptor.Singleton<IAuthorizationContextValidator,
                Authorization.Validation.RequiredAuthContextClassRefValidator>(),
            ServiceDescriptor.Singleton<IAuthorizationContextValidator, NonceValidator>(),
            ServiceDescriptor.Singleton<IAuthorizationContextValidator, Authorization.Validation.ResourceValidator>(),
            ServiceDescriptor.Singleton<IAuthorizationContextValidator, Authorization.Validation.ScopeValidator>(),
            ServiceDescriptor.Singleton<IAuthorizationContextValidator, PkceValidator>(),
            ServiceDescriptor.Singleton<IAuthorizationContextValidator, ProofKeyThumbprintValidator>(),
            ServiceDescriptor.Singleton<IAuthorizationContextValidator, AuthorizationDetailsRequestValidator>()
        ]);
        return services.Compose<IAuthorizationContextValidator, AuthorizationContextValidatorComposite>();
    }
}
