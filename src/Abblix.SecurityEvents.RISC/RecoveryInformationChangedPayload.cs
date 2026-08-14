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

using Abblix.SecurityEvents.Events;

namespace Abblix.SecurityEvents.RISC;

/// <summary>
/// Recovery Information Changed (RISC 1.0 Section 2.10): the account identified by the subject
/// changed some of its recovery information - a recovery email added or removed, or an
/// identifier change at a provider NOT authoritative over the identifier, which Section 2.5
/// routes here instead of Identifier Changed. The event carries no attributes.
/// </summary>
public sealed record RecoveryInformationChangedPayload : IEventPayload;
