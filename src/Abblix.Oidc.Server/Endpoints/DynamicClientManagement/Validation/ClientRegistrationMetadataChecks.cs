// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// The checks of a dynamic client registration that judge the client's metadata rather than the request carrying it.
/// </summary>
internal static class ClientRegistrationMetadataChecks
{
    /// <summary>
    /// The checks of a registration that judge the client's metadata rather than the request carrying it, in the order
    /// the pipeline runs them. A client resolved from its metadata document is judged by these alone
    /// (<c>ClientIdMetadataDocumentValidator</c>), so a check added here judges both.
    /// </summary>
    public static readonly ServiceDescriptor[] All =
    [
        ServiceDescriptor.Singleton<IClientRegistrationContextValidator, RedirectUrisValidator>(),
        ServiceDescriptor.Singleton<IClientRegistrationContextValidator, PostLogoutRedirectUrisValidator>(),
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
        ServiceDescriptor.Singleton<IClientRegistrationContextValidator, ScopeValidator>(),
        ServiceDescriptor.Singleton<IClientRegistrationContextValidator, HostGrantedMetadataValidator>(),
        ServiceDescriptor.Singleton<IClientRegistrationContextValidator, SoftwareStatementValidator>(),
        ServiceDescriptor.Singleton<IClientRegistrationContextValidator, SubjectTypeValidator>(),
        ServiceDescriptor.Singleton<IClientRegistrationContextValidator, InitiateLoginUriValidator>(),
        ServiceDescriptor.Singleton<IClientRegistrationContextValidator, OfflineAccessValidator>(),
        ServiceDescriptor.Singleton<IClientRegistrationContextValidator, BackChannelLogoutUriValidator>(),
        ServiceDescriptor.Singleton<IClientRegistrationContextValidator, JwksUriValidator>(),
        ServiceDescriptor.Singleton<IClientRegistrationContextValidator, StoredUriValidator>(),
        ServiceDescriptor.Singleton<IClientRegistrationContextValidator, BackChannelAuthenticationValidator>(),
        ServiceDescriptor.Singleton<IClientRegistrationContextValidator, SigningAlgorithmsValidator>(),
        ServiceDescriptor.Singleton<IClientRegistrationContextValidator, SignedResponseAlgorithmsValidator>(),
        // After the check that a named algorithm is one this server supports at all, so a profile's narrower
        // refusal is not reported for an algorithm the server cannot sign with in any case
        ServiceDescriptor.Singleton<IClientRegistrationContextValidator, ProfileSigningKeysValidator>(),
        ServiceDescriptor.Singleton<IClientRegistrationContextValidator, EncryptedResponseAlgorithmsValidator>(),
        ServiceDescriptor.Singleton<IClientRegistrationContextValidator, TokenEndpointAuthMethodValidator>(),
        ServiceDescriptor.Singleton<IClientRegistrationContextValidator, CredentialsValidator>(),
        ServiceDescriptor.Singleton<IClientRegistrationContextValidator, TlsClientAuthValidator>(),
        ServiceDescriptor.Singleton<IClientRegistrationContextValidator, AuthorizationDetailsTypesValidator>(),
    ];
}
