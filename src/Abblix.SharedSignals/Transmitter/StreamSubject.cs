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

using Abblix.SecurityEvents.Subjects;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// A subject the receiver added to a stream, with the verification statement it made about it
/// (SSF 1.0 Section 8.1.3.2): an omitted "verified" is assumed true, so the flag here is what
/// the request MEANT, resolved by the management layer before storing.
/// </summary>
/// <param name="Subject">The added subject, in any Identifier Format.</param>
/// <param name="Verified">Whether the receiver has verified the subject claim.</param>
public sealed record StreamSubject(SubjectIdentifier Subject, bool Verified);
