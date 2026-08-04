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

namespace Abblix.SecurityEvents.Risc;

/// <summary>
/// Opt Out Effective (RISC 1.0 Section 2.8.4): the opt-out took effect and the account
/// identified by the subject no longer participates in RISC event exchanges - the last event
/// the receiver will see for it. The event carries no attributes.
/// </summary>
public sealed record OptOutEffectivePayload : IEventPayload;
