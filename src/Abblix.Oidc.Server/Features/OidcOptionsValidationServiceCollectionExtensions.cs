// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features;

/// <summary>
/// Registers the validators that judge <see cref="OidcOptions"/> when the host starts, and the checks that judge
/// each tenant's own settings wherever a tenant enters the server.
/// </summary>
internal static class OidcOptionsValidationServiceCollectionExtensions
{
    /// <summary>
    /// Registers the startup validators of <see cref="OidcOptions"/> and the checks of the tenants' settings.
    /// </summary>
    /// <remarks>
    /// Called by <see cref="ServiceCollectionExtensions.AddClientInformation"/>, so every host that serves clients
    /// has its settings judged before it starts.
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the validators to.</param>
    public static IServiceCollection AddOidcOptionsValidators(this IServiceCollection services)
    {
        // Fail loud at startup when a security profile removes a control without the ones replacing it
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, SecurityProfileRelaxationsValidator>());

        // Fail loud at startup when a configured secret-bearing length is below the security floor
        // for its kind, instead of generating a guessable secret or an unusable HMAC key at runtime.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, SecretLengthOptionsValidator>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, RevocationRetentionOptionsValidator>());

        // Fail loud at startup when EnabledEndpoints advertises an opt-in endpoint whose feature services were
        // never registered by the matching AddX() call, instead of 500-ing on every request to it.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, EnabledEndpointsRegistrationValidator>());

        // Fail loud at startup when a ServiceTokens signing or encryption algorithm is not one the registered
        // signers/encryptors can produce, instead of failing per-request at token issuance.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, ServiceTokensAlgorithmsValidator>());

        // Refuse a registration body limit that would answer every request with a refusal, which surfaces as
        // a broken endpoint rather than as the misconfiguration it is.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, RegistrationRequestSizeValidator>());

        // Refuse revoked initial access token subjects left in the server options, where nothing reads them
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, RevokedInitialAccessTokenSubjectsValidator>());

        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, ClockSkewValidator>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, FingerprintKeyValidator>());

        // Refuse a tenant whose clients, resources or keys the server could not serve, wherever it enters the
        // server, instead of failing every request that meets the contradiction without naming it
        services.TryAddEnumerable([
            ServiceDescriptor.Singleton<ITenantsCheck, SecurityProfileCheck>(),
            ServiceDescriptor.Singleton<ITenantsCheck, ClientSecretsCheck>(),
            ServiceDescriptor.Singleton<ITenantsCheck, ClientIdsCheck>(),
            ServiceDescriptor.Singleton<ITenantsCheck, ClientOfflineAccessCheck>(),
            ServiceDescriptor.Singleton<ITenantsCheck, RefreshTokenReusePolicyCheck>(),
            ServiceDescriptor.Singleton<ITenantsCheck, PairwiseClientsCheck>(),
            ServiceDescriptor.Singleton<ITenantsCheck, ResourceDefinitionsCheck>(),
            ServiceDescriptor.Singleton<ITenantsCheck, DefaultResourceIndicatorCheck>(),
            ServiceDescriptor.Singleton<ITenantsCheck, ServiceTokenEncryptionKeysCheck>(),
            ServiceDescriptor.Singleton<ITenantsCheck, ClockSkewCeilingCheck>(),
            ServiceDescriptor.Singleton<ITenantsCheck, BackChannelClientAuthenticationCheck>(),
        ]);

        return services;
    }
}
