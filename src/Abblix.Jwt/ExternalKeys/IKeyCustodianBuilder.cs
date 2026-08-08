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

using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// The continuation of a custodian registration: the host has said WHICH custodian holds its keys and must now say
/// HOW the library uses it. These are two independent choices, and the second one is the security posture - where
/// the private half of a key lives - so it is named at the call site and never defaulted. The choices are
/// <c>UseKeysInCustodian</c>, where the private half never enters this process and every signature and every CEK
/// unwrap is a round-trip to the custodian, and <c>UseKeysInProcess</c>, where the library mints its own keys and
/// the custodian only seals them.
/// </summary>
/// <remarks>
/// A host that drops this builder without naming a placement fails at startup, rather than falling back silently to
/// whatever keys its configuration happens to carry - which would leave a configured custodian, a clean log, and
/// local keys.
/// </remarks>
public interface IKeyCustodianBuilder
{
    /// <summary>The collection the placement call registers its key provider into.</summary>
    IServiceCollection Services { get; }
}
