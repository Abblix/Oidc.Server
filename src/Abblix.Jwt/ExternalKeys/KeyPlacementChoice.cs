// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Records where the host chose to keep its private keys for its registered custodian, so the choice can be checked at startup rather
/// than at the first key operation.
/// </summary>
/// <remarks>
/// Riding the options-validation pipeline is what buys the timing: <c>ValidateOnStart</c> registers an
/// <c>IStartupValidator</c>, and the host runs it BEFORE it starts any hosted service, including the one that
/// opens the HTTP port. A hosted service of our own would only run once that port is already open. The state
/// lives here rather than on <c>OidcOptions</c> because validating those would resolve the key provider, which
/// itself depends on those same options.
/// </remarks>
public sealed class KeyPlacementChoice
{
    /// <summary>
    /// Where the placement call put the private halves, or null when no placement call ran. Recording the choice
    /// rather than inspecting the registered provider keeps the check independent of a host that layers its own
    /// provider over the placement's.
    /// </summary>
    public KeyPlacement? ChosenPlacement { get; set; }

    /// <summary>
    /// What a host is told when it registered a custodian and never said how its keys are used.
    /// </summary>
    /// <remarks>
    /// Held here rather than on whichever guard reports it, because more than one does: the startup validation
    /// says it when the host has a lifetime to run validators, and the key provider says it when something asks
    /// for keys without one. Two guards saying different things about the same omission would read as two
    /// different problems.
    /// </remarks>
    public const string PlacementNotChosenMessage =
        "A key custodian is registered, but where its private keys live was never chosen. "
        + $"Follow the custodian registration with {nameof(ExternalKeysServiceCollectionExtensions.UseKeysInCustodian)}"
        + "() to keep the private half inside the custodian, or "
        + $"{nameof(ExternalKeysServiceCollectionExtensions.UseKeysInProcess)}() to mint keys locally and seal them "
        + "to it.";
}
