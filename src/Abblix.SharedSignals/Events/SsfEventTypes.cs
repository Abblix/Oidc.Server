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

namespace Abblix.SharedSignals.Events;

/// <summary>
/// The event type URIs of the events SSF 1.0 itself defines - the framework's own signals about
/// a stream, as opposed to the CAEP and RISC events that ride on it.
/// </summary>
public static class SsfEventTypes
{
#pragma warning disable S1075 // URIs should not be hardcoded - these are the specification-fixed event type identifiers, not configuration
    /// <summary>
    /// The Verification Event a receiver requests to confirm a stream is configured correctly,
    /// end to end (SSF 1.0 Section 8.1.4.1).
    /// </summary>
    public const string Verification = "https://schemas.openid.net/secevent/ssf/event-type/verification";

    /// <summary>
    /// The Stream Updated Event a transmitter must send when it changes a stream's status on its
    /// own - before stopping the stream on a pause or disable, and upon re-enabling it
    /// (SSF 1.0 Section 8.1.5).
    /// </summary>
    public const string StreamUpdated = "https://schemas.openid.net/secevent/ssf/event-type/stream-updated";
#pragma warning restore S1075
}
