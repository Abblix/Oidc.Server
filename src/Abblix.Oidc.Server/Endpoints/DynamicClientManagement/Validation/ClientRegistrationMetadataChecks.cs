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
    /// The metadata checks of a dynamic registration, in the order the pipeline runs them: the software statement
    /// step first, since the metadata a trusted statement carries replaces the request's (RFC 7591 section 3.1.1) and
    /// every check after it judges the values the client is registered with, then <see cref="MetadataDocument"/>.
    /// </summary>
    public static ServiceDescriptor[] Registration =>
    [
        ServiceDescriptor.Singleton<IClientRegistrationContextValidator, SoftwareStatementValidator>(),
        ..MetadataDocument,
    ];

    /// <summary>
    /// The checks a client resolved from its metadata document is judged by (<c>ClientIdMetadataDocumentValidator</c>),
    /// which every registration runs too, so a check added here judges both. A document is the client's own
    /// assertion under rules its reader fixes, so a <c>software_statement</c> it carries is neither validated nor
    /// applied.
    /// </summary>
    public static readonly ServiceDescriptor[] MetadataDocument =
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
        // After the method is known to be one this server supports, so an unsupported method is reported as such
        ServiceDescriptor.Singleton<IClientRegistrationContextValidator, ConfidentialGrantTypeValidator>(),
        ServiceDescriptor.Singleton<IClientRegistrationContextValidator, PkceOptOutValidator>(),
        ServiceDescriptor.Singleton<IClientRegistrationContextValidator, CredentialsValidator>(),
        ServiceDescriptor.Singleton<IClientRegistrationContextValidator, TlsClientAuthValidator>(),
        ServiceDescriptor.Singleton<IClientRegistrationContextValidator, AuthorizationDetailsTypesValidator>(),
    ];
}
