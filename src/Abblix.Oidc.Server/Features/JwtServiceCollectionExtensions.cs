// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Implementation;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ExternalKeys;
using Abblix.Oidc.Server.Features.ResponseObject;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features;

/// <summary>
/// Provides extension methods to <see cref="IServiceCollection"/> for configuring
/// formatting and validating the JWTs this server and its clients sign.
/// </summary>
public static class JwtServiceCollectionExtensions
{
    /// <summary>
    /// Registers JWT formatting and validation services for authentication within the specified <see cref="IServiceCollection"/>.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the JWT authentication services to.</param>
    /// <returns>The <see cref="IServiceCollection"/> for chaining further service registrations.</returns>
    public static IServiceCollection AddAuthServiceJwt(this IServiceCollection services)
    {
        // Which provider serves this server's keys follows from where the host put the private halves, and that
        // choice is made by a call in Abblix.Jwt which may run either side of this one. So it is read at resolve
        // rather than acted on at registration: nothing here has to be ordered against the placement call, and a
        // host that never wires a custodian simply lands on the static-configuration provider.
        //
        // TryAdd, so a host that registered its own key provider keeps it whichever placement it then chooses -
        // which is how the custodian's key listing gets cached in production, since the provider below does not
        // cache. The placement decides what the LIBRARY would install, never that one must be installed.
        services.TryAddSingleton<IAuthServiceKeysProvider>(serviceProvider =>
            serviceProvider.GetRequiredService<IOptions<KeyPlacementChoice>>().Value.ChosenPlacement switch
            {
                // No custodian at all, or one registered with the placement call forgotten. This provider reads the
                // static keys of OidcOptions and refuses outright in the second case, so a half-wired host cannot
                // quietly serve local keys while believing its keys are in an HSM.
                null => serviceProvider.CreateService<OidcOptionsKeysProvider>(),

                KeyPlacement.Custodian => serviceProvider.CreateService<ExternalKeysProvider>(),
                KeyPlacement.InProcess => serviceProvider.CreateService<MintedKeysProvider>(),

                var unknown => throw new InvalidOperationException(
                    $"No {nameof(IAuthServiceKeysProvider)} serves the {nameof(KeyPlacement)} '{unknown}'."),
            });

        // The write-role counterpart to the reader above. The default is the read-only static
        // configuration that fails loud if asked to persist a generated key; a persistent store (shipped
        // with key generation and rotation) replaces it host-first via TryAdd. It is segregated from the
        // reader (ISP), so read-only consumers never depend on persistence.
        services.TryAddSingleton<IAuthServiceKeysStore, ReadOnlyAuthServiceKeysStore>();

        // Fail loud at startup when the resolved provider is the static one above and OidcOptions carries no
        // signing key: that host can never sign a token, and without this check the first symptom is an empty
        // JWKS cached by every relying party. A host-supplied provider is trusted, not probed - its store may
        // be legitimately unreachable while the host boots.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, SigningKeysPresenceValidator>());

        services.TryAddSingleton<IAuthServiceJwtFormatter, AuthServiceJwtFormatter>();
        services.TryAddSingleton<IAuthServiceJwtValidator, AuthServiceJwtValidator>();
        services.TryAddSingleton<IIdTokenHintParser, IdTokenHintParser>();
        return services;
    }

    /// <summary>
    /// Registers services for validating and formatting JWTs used in client authentication scenarios within
    /// the specified <see cref="IServiceCollection"/>.
    /// </summary>
    /// <remarks>
    /// This method adds services to the <see cref="IServiceCollection"/> that are responsible for validating and
    /// formatting JWTs used specifically in client authentication.
    /// These services ensure that JWTs conform to the required standards,
    /// include all necessary claims, and are properly validated for client authentication processes.
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the client JWT validation and
    /// formatting services to.</param>
    /// <returns>The <see cref="IServiceCollection"/> for chaining further service registrations.</returns>
    public static IServiceCollection AddClientJwt(this IServiceCollection services)
    {
        services.TryAddSingleton<IClientJwtValidator, ClientJwtValidator>();

        // The validator judges a client JWT's timestamps against this clock. Registered here rather
        // than relied upon from elsewhere: this method is public and a host may call it on a
        // collection that has nothing else of ours in it.
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IClientJwtFormatter, ClientJwtFormatter>();
        services.TryAddSingleton<IResponseJwtBuilder, ResponseJwtBuilder>();
        return services;
    }
}
