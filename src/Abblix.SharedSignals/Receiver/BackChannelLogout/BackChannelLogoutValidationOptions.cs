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

using System.Diagnostics.CodeAnalysis;
using Abblix.SecurityEvents.Validation;

namespace Abblix.SharedSignals.Receiver.BackChannelLogout;

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
