// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Jwt.Signing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Records where a custodian's private keys live and puts the external backends on the crypto seams.
/// </summary>
internal static class KeyPlacementServiceCollectionExtensions
{
    /// <summary>
    /// Arms the startup check that a placement was chosen, and hands back the builder to choose it with.
    /// </summary>
    internal static IKeyCustodianBuilder OpenKeyPlacement(this IServiceCollection services)
    {
        // Turns a missing placement call into a startup failure rather than a first-use one: the host runs its
        // startup validators before it starts the hosted service that opens the port, so the process never
        // serves a request in this state.
        services.AddOptions<KeyPlacementChoice>()
            .Validate(choice => choice.ChosenPlacement is not null, KeyPlacementChoice.PlacementNotChosenMessage)
            .ValidateOnStart();

        // Armed with the custodian rather than with the call naming its keys, because a host may register the keys
        // itself and then choose the placement without naming any; with no encryption key held the check passes
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<KeyPlacementChoice>, CustodianEncryptionAlgorithmCheck>());

        return new KeyCustodianBuilder(services);
    }

    /// <summary>
    /// The half both placements share: refuse an ordering that would compose nothing, record the choice, and put
    /// the external backends on the crypto seams.
    /// </summary>
    /// <remarks>
    /// The external backends belong to the PLACEMENT rather than to the custodian, because they route a private
    /// operation out of process, which is what a placement decides. Both placements need them: the minting one
    /// signs locally but still opens each sealed key through the custodian, and that unwrap is external.
    /// </remarks>
    internal static IServiceCollection ChooseKeyPlacement(
        this IKeyCustodianBuilder builder,
        KeyPlacement placement,
        string placementCall)
    {
        var services = builder.Services;

        // Composition needs the in-process backends to compose WITH, and Compose short-circuits on a one-member
        // family: running before the JWT registration would build no composite, and the external backend would then
        // lose the singular resolve to the local one registered after it. Nothing detects that later - the seam
        // simply reports it cannot sign a key it should have routed here - so fail where the mistake is.
        //
        // Only AddJsonWebTokens is named. Whichever registration the host wrote performs it (an OpenID Provider's
        // does, and so does the security-event one), and naming those here would be a literal for a method in an
        // assembly this one does not reference: nothing would keep it true through a rename, and it would advise a
        // host that has no such method to call it.
        if (services.All(descriptor => descriptor.ServiceType != typeof(IDataSigner)))
            throw new InvalidOperationException(
                $"Call {placementCall} after {nameof(ServiceCollectionExtensions.AddJsonWebTokens)}, which every "
                + "registration that adds JSON Web Token services performs. It composes the external crypto "
                + "backends with their in-process peers, and none are registered yet.");

        // A placement says where a CUSTODIAN's keys live, so one without a custodian is half a sentence. It
        // would otherwise pass every guard here and at startup - the placement is recorded, so the choice looks
        // made - and surface on the first key operation as the container's own "unable to resolve IKeyCustodian",
        // which names neither this call nor the registration that is missing.
        var custodian = services.LastOrDefault(descriptor => descriptor.ServiceType == typeof(IKeyCustodian))
            ?? throw new InvalidOperationException(
                $"{placementCall} says where a key custodian's private keys live, but no {nameof(IKeyCustodian)} "
                + "is registered. Register one first - "
                + $"{nameof(ExternalKeysServiceCollectionExtensions.AddCustodian)} does it, as does each backend "
                + "package's own AddVaultCustodian or AddAzureCustodian.");

        // The backends that route a private operation out of process are singletons, so a custodian shorter-lived
        // than they are is a captive dependency. It would be caught by ValidateScopes in Development and by nothing
        // at all in Production, where the first resolve pins one scope's custodian for the process lifetime.
        if (custodian.Lifetime != ServiceLifetime.Singleton)
            throw new InvalidOperationException(
                $"{nameof(IKeyCustodian)} is registered as {custodian.Lifetime} and must be a "
                + $"{ServiceLifetime.Singleton}: the signing and decryption backends that reach it are singletons, "
                + "so a shorter lifetime would pin one scope's custodian for the life of the process.");

        // Satisfies the startup validation the custodian registration armed: the wiring is now complete.
        services.Configure<KeyPlacementChoice>(choice => choice.ChosenPlacement = placement);

        services.ComposeExternalKeyBackends();
        return services;
    }
}
