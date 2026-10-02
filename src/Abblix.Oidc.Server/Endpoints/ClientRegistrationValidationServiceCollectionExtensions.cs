// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Server.Endpoints;

/// <summary>
/// Registers the validation pipeline every dynamic client registration passes through.
/// </summary>
internal static class ClientRegistrationValidationServiceCollectionExtensions
{
    /// <summary>
    /// Registers the client registration context validators and composes them, in order, into one validator.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    internal static IServiceCollection AddClientRegistrationContextValidators(this IServiceCollection services)
    {
        // compose ClientRegistrationContext validation as a pipeline of several IClientRegistrationContextValidator
        services.TryAddEnumerable([
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, InitialAccessTokenValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, ClientIdValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, RedirectUrisValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, DynamicClientManagement.Validation.PostLogoutRedirectUrisValidator>(),
            // Server-level support gates run before the consistency check so the rejection message
            // surfaces "this server doesn't support that" rather than the more confusing
            // "your response_types/grant_types are inconsistent" from GrantTypeValidator.
            // Scoped: these gates consume IEnumerable<IAuthorizationResponseBuilder> /
            // IEnumerable<IGrantTypeInformer>, which include the scoped IdTokenResponseBuilder
            // once EnableImplicitFlow() is called.
            ServiceDescriptor.Scoped<IClientRegistrationContextValidator, SupportedResponseTypeValidator>(),
            ServiceDescriptor.Scoped<IClientRegistrationContextValidator, SupportedGrantTypeValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, GrantTypeValidator>(),
            // Fail-loud profile self-consistency: runs after the response/grant-type gates so an
            // unsupported or inconsistent type is reported as such before this surfaces a
            // profile-specific rejection.
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, SecurityProfileValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, DynamicClientManagement.Validation.ScopeValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, SoftwareStatementValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, SubjectTypeValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, InitiateLoginUriValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, BackChannelLogoutUriValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, JwksUriValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, StoredUriValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, BackChannelAuthenticationValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, SigningAlgorithmsValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, SignedResponseAlgorithmsValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, EncryptedResponseAlgorithmsValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, TokenEndpointAuthMethodValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, CredentialsValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, TlsClientAuthValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, AuthorizationDetailsTypesValidator>()
        ]);
        return services.Compose<IClientRegistrationContextValidator, ClientRegistrationContextValidatorComposite>();
    }
}
