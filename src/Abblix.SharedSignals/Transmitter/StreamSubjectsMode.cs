// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// Which subjects a stream covers by default - the per-stream fixation of the transmitter's
/// "default_subjects" advertisement (SSF 1.0 Section 7.1), taken at stream creation so a later
/// change of the advertisement does not silently re-scope existing streams.
/// </summary>
public enum StreamSubjectsMode
{
    /// <summary>
    /// Every subject appropriate for the stream is on it until removed: the receiver's removals
    /// carve subjects out, and its additions bring carved-out subjects back
    /// (SSF 1.0 Section 7.1, "ALL").
    /// </summary>
    All,

    /// <summary>
    /// No subject is on the stream until the receiver adds it (SSF 1.0 Section 7.1, "NONE").
    /// </summary>
    None,
}
