// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Abblix.Oidc.Server.Features.ScopeManagement;
using Abblix.Oidc.Server.Features.UserInfo;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features;

/// <summary>
/// Provides extension methods to <see cref="IServiceCollection"/> for configuring user claims and subject identifiers.
/// </summary>
public static class UserInfoServiceCollectionExtensions
{
    /// <summary>
    /// Registers services related to user claims management into the provided <see cref="IServiceCollection"/>.
    /// This method sets up essential services required for processing and handling user claims based on authentication
    /// sessions and authorization requests, facilitating the integration of user-specific data into tokens or responses.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to which the user claims provider services will be
    /// added. This collection is a mechanism for adding and retrieving dependencies in .NET applications, often used
    /// to configure dependency injection in ASP.NET Core applications.</param>
    /// <returns>The updated <see cref="IServiceCollection"/> after adding the services, allowing for further
    /// modifications and additions to be chained.</returns>
    public static IServiceCollection AddUserInfo(this IServiceCollection services)
    {
        services.TryAddScoped<IUserClaimsProvider, UserClaimsProvider>();
        services.TryAddSingleton<ISubjectTypeConverter, IssuerSubjectTypeConverter>();
        services.TryAddSingleton<IScopeClaimsProvider, ScopeClaimsProvider>();
        services.TryAddSingleton<IScopeManager, ScopeManager>();
        services.TryAddSingleton<IResourceManager, ResourceManager>();
        services.TryAddSingleton<IResourceKeysProvider, ResourceKeysProvider>();
        services.TryAddSingleton<IAudienceKeyResolver, AudienceKeyResolver>();
        return services;
    }

    /// <summary>
    /// Registers pairwise subject identifier settings, enabling reversible per-sector subject conversion for clients
    /// with SubjectType=pairwise. The salt and hash algorithm key a deterministic authenticated-encryption seal that
    /// produces stable, per-sector pseudonyms the server can open back to the real subject, per OpenID Connect Core
    /// Section 8.1.
    /// </summary>
    /// <param name="services">The service collection to register settings into.</param>
    /// <param name="settings">The pairwise subject settings containing the seal key (salt) and hash algorithm.</param>
    /// <exception cref="ArgumentException">The salt is missing, not valid base64, or too short.</exception>
    /// <remarks>
    /// Judged here as well as by <see cref="PairwiseSubjectSettings.Salt"/>, and the two answer about different
    /// instances rather than about one fact twice. The property covers every instance somebody WRITES - an
    /// object initializer, a <c>with</c> expression - and it is the only place that can, since the extension
    /// registers with <c>TryAddSingleton</c> and a host's own instance wins.
    ///
    /// It cannot cover an instance the configuration binder BUILDS. <c>required</c> is a compiler rule: the
    /// binder constructs the object and then sets only the properties whose keys are present, so an absent
    /// <c>Pairwise:Salt</c> never enters the accessor and the seal key is null with nothing raised - measured,
    /// not assumed. Left to reach the container that way, it surfaces as a 500 from the token endpoint the
    /// first time a pairwise identifier is minted, which is the failure this check exists to move to startup.
    /// </remarks>
    public static IServiceCollection AddPairwiseSubjectIdentifiers(
        this IServiceCollection services,
        PairwiseSubjectSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        PairwiseSubjectSettings.ValidateSalt(settings.Salt);

        services.TryAddSingleton(settings);
        return services;
    }

    /// <summary>
    /// Wires pairwise subject identifiers over settings the host has already bound, and refuses an unusable
    /// seal key before the host serves anything.
    /// </summary>
    /// <param name="services">The service collection the host bound its settings into.</param>
    /// <remarks>
    /// The way to configure this from a file: the host binds the section - <c>services.Configure</c>, or
    /// <c>AddOptions().Bind()</c> - and this call judges the result. The library takes no dependency on the
    /// configuration stack for it, which is why the binding stays the host's.
    ///
    /// Riding the options pipeline is what buys the timing: its validators run before the host starts the
    /// service that opens the port, so a deployment whose seal key will not do never serves a request. An
    /// unusable key reaching the container instead surfaces as a 500 from the token endpoint the first time
    /// a pairwise identifier is minted, which names neither the setting nor the deployment that changed it.
    ///
    /// This is also the only shape that judges the instance actually IN USE. A check over an argument judges
    /// what it was handed, and the overload above registers with <c>TryAddSingleton</c>, so a host that
    /// brought its own settings keeps them.
    /// </remarks>
    public static IServiceCollection AddPairwiseSubjectIdentifiers(this IServiceCollection services)
    {
        services.AddOptions<PairwiseSubjectSettings>().ValidateOnStart();

        // TryAddEnumerable because the options framework resolves every registered validator, and a second
        // copy of this one would report the same refusal twice.
        services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IValidateOptions<PairwiseSubjectSettings>, PairwiseSubjectSettingsValidator>());

        // Resolved from the options rather than registered beside them, so there is one instance and the
        // thing validated is the thing handed out.
        services.TryAddSingleton(provider =>
            provider.GetRequiredService<IOptions<PairwiseSubjectSettings>>().Value);

        return services;
    }
}
