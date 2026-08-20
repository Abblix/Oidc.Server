// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
    /// <summary>The collection the placement call records its choice into.</summary>
    IServiceCollection Services { get; }
}
