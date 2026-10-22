// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Common.Implementation;
using Abblix.Oidc.Server.Common.Interfaces;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.ExternalKeys;

/// <summary>
/// Tells which key provider serves the server's keys - the one the library installs for the host's key placement,
/// or one the host registered - without building it.
/// </summary>
/// <remarks>
/// The checks that judge each tenant's keys run while the server's settings are validated, and a host's own provider
/// may take the key ring, whose settings are completed from the server's: building the provider there to ask its
/// type would build it inside its own construction. So the answer is read from the registrations the server was added
/// to, where the last one for the provider is the one the built-in container serves, and where a host registers a
/// provider of its own (<see cref="IAuthServiceKeysProvider"/>). They are read while the container runs rather than
/// copied while registering, since a host may register its provider after the server.
/// </remarks>
/// <param name="services">The registrations the server was added to.</param>
/// <param name="placement">Where the host placed the private halves of its keys, if anywhere.</param>
internal sealed class KeyProviderRegistration(IServiceCollection services, IOptions<KeyPlacementChoice> placement)
{
    /// <summary>
    /// The factory the library registers its provider with, held once so the registration serving the provider can
    /// be recognized as the library's by reference.
    /// </summary>
    internal static readonly Func<IServiceProvider, object> LibraryProvider = CreateLibraryProvider;

    /// <summary>
    /// The provider serving the keys.
    /// </summary>
    public KeyProviderKind Kind
    {
        get
        {
            var serving = services.LastOrDefault(descriptor =>
                descriptor.ServiceType == typeof(IAuthServiceKeysProvider) && !descriptor.IsKeyedService);

            if (ReferenceEquals(serving?.ImplementationFactory, LibraryProvider))
                return Placed;

            return KeyProviderKind.Host;
        }
    }

    /// <summary>
    /// Whether the server mints its keys into the key ring and serves them from there, so the ring of each tenant is
    /// the server's to open and to delete.
    /// </summary>
    public bool Mints => Kind switch
    {
        KeyProviderKind.Minted => true,
        KeyProviderKind.Settings or KeyProviderKind.Custodian or KeyProviderKind.Host => false,
        var unknown => throw new InvalidOperationException($"Unexpected {nameof(KeyProviderKind)} '{unknown}'."),
    };

    /// <summary>
    /// The provider the library installs for the host's key placement.
    /// </summary>
    /// <remarks>
    /// No custodian at all, or one registered with the placement call forgotten, lands on the settings: that
    /// provider refuses outright in the second case, so a half-wired host cannot quietly serve local keys while
    /// believing its keys are in an HSM.
    /// </remarks>
    private KeyProviderKind Placed => placement.Value.ChosenPlacement switch
    {
        null => KeyProviderKind.Settings,
        KeyPlacement.Custodian => KeyProviderKind.Custodian,
        KeyPlacement.InProcess => KeyProviderKind.Minted,
        var unknown => throw new InvalidOperationException(
            $"No {nameof(IAuthServiceKeysProvider)} serves the {nameof(KeyPlacement)} '{unknown}'."),
    };

    private static IAuthServiceKeysProvider CreateLibraryProvider(IServiceProvider serviceProvider)
        => serviceProvider.GetRequiredService<KeyProviderRegistration>().Placed switch
        {
            KeyProviderKind.Settings => serviceProvider.CreateService<OidcOptionsKeysProvider>(),
            KeyProviderKind.Custodian => serviceProvider.CreateService<ExternalKeysProvider>(),
            KeyProviderKind.Minted => serviceProvider.CreateService<MintedKeysProvider>(),

            // A placement names one of the library's providers, never the host's
            KeyProviderKind.Host => throw new InvalidOperationException(
                $"No key placement names a {nameof(KeyProviderKind.Host)} provider."),

            var unknown => throw new InvalidOperationException(
                $"The library installs no {nameof(IAuthServiceKeysProvider)} of the kind '{unknown}'."),
        };
}
