// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Diagnostics.CodeAnalysis;
using Abblix.SecurityEvents.Validation;

namespace Abblix.SecurityEvents.BackChannelLogout;

/// <summary>
/// What a back-channel logout receiver expects of every Logout Token: the provider it talks to as
/// the issuer, its own client identifier as the audience, and the clock tolerance it allows.
/// </summary>
/// <remarks>
/// It adds no member to the base, and exists for the one thing a base type cannot supply: its own
/// identity in the container. A host running this receiver beside a Shared Signals one holds two
/// sets of expectations that are the same shape and must never be swapped - the audience here is
/// this client, there it is the stream's receiver - and a single registration of the base type
/// would let whichever ran last answer for both.
/// </remarks>
[SuppressMessage("Major Code Smell", "S2094:Classes should not be empty",
    Justification = "The empty body is the point: this type carries no data of its own and exists to be a "
        + "distinct service identity, so a host running two receivers cannot resolve one's expectations for "
        + "the other. Adding a member would not make it more useful, and an interface cannot be registered "
        + "as the base type's value.")]
public sealed record BackChannelLogoutValidationOptions : SecurityEventTokenValidationOptions;
