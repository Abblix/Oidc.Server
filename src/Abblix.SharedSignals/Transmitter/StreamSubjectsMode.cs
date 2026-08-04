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
