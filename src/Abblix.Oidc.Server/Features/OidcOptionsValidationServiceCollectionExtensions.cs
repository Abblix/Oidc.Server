// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features;

/// <summary>
/// Registers the validators that judge <see cref="OidcOptions"/> when the host starts.
/// </summary>
internal static class OidcOptionsValidationServiceCollectionExtensions
{
    /// <summary>
    /// Registers the startup validators of <see cref="OidcOptions"/>.
    /// </summary>
    /// <remarks>
    /// Called by <see cref="ServiceCollectionExtensions.AddClientInformation"/>, so every host that serves clients
    /// has its settings judged before it starts.
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the validators to.</param>
    /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
    public static IServiceCollection AddOidcOptionsValidators(this IServiceCollection services)
    {
        // Fail loud at startup when a statically-configured client cannot satisfy its effective
        // security profile, instead of letting the contradiction surface per-request. TryAddEnumerable
        // because the options framework resolves every registered IValidateOptions.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, OidcOptionsSecurityProfileValidator>());

        // Fail loud at startup when a configured secret-bearing length is below the security floor
        // for its kind, instead of generating a guessable secret or an unusable HMAC key at runtime.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, SecretLengthOptionsValidator>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, RevocationRetentionOptionsValidator>());

        // Fail loud at startup when a client that authenticates by shared secret has none, or carries a
        // hash of the wrong length, instead of refusing that client on every request it ever makes.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, ClientSecretsOptionsValidator>());

        // Fail loud at startup when the host keeps registrations for tenants on a server without them, where its
        // store would never be asked and the registrations would stay in memory
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, TenantClientRegistrationStoreValidator>());

        // Fail loud at startup when the client or resource registry could not hold what is configured, instead
        // of failing every request that builds it, without naming what it could not hold.
        services.TryAddEnumerable([
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, ClientIdsOptionsValidator>(),
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, RefreshTokenReusePolicyValidator>(),
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, PairwiseClientsOptionsValidator>(),
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, ResourceDefinitionsValidator>(),
        ]);

        // Fail loud at startup when EnabledEndpoints advertises an opt-in endpoint whose feature services were
        // never registered by the matching AddX() call, instead of 500-ing on every request to it.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, EnabledEndpointsRegistrationValidator>());

        // Fail loud at startup when a ServiceTokens signing or encryption algorithm is not one the registered
        // signers/encryptors can produce, instead of failing per-request at token issuance.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, ServiceTokensAlgorithmsValidator>());

        // Refuse a default resource indicator that no resource server could accept, rather than minting every
        // access token with an audience nothing recognizes.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, DefaultResourceIndicatorValidator>());

        // Refuse a registration body limit that would answer every request with a refusal, which surfaces as
        // a broken endpoint rather than as the misconfiguration it is.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, RegistrationRequestSizeValidator>());

        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, ClockSkewCeilingValidator>());
        return services;
    }
}
