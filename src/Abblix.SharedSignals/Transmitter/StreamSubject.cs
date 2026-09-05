// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
