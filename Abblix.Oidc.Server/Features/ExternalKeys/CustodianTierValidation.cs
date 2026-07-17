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

namespace Abblix.Oidc.Server.Features.ExternalKeys;

/// <summary>
/// Records which tier the host chose for its registered custodian, so the choice can be checked at startup rather
/// than at the first key operation.
/// </summary>
/// <remarks>
/// Riding the options-validation pipeline is what buys the timing: <c>ValidateOnStart</c> registers an
/// <c>IStartupValidator</c>, and the host runs it BEFORE it starts any hosted service, including the one that
/// opens the HTTP port. A hosted service of our own would only run once that port is already open. The state
/// lives here rather than on <c>OidcOptions</c> because validating those would resolve the key provider, which
/// itself depends on those same options.
/// </remarks>
internal sealed class CustodianTierValidation
{
    /// <summary>
    /// The tier call that completed the custodian wiring, or null when none did. Recording the name rather than
    /// inspecting the registered provider keeps the check independent of a host that layers its own provider
    /// over the tier's.
    /// </summary>
    public string? ChosenTier { get; set; }
}
