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

namespace Abblix.SecurityEvents.Caep;

/// <summary>
/// Session Revoked (CAEP 1.0 Section 3.1): the session identified by the subject has been
/// revoked. The event carries no claims of its own - the subject names the session, directly
/// or through the properties of a complex subject, in which case the revocation applies to any
/// session matching the combined claims; when <see cref="CaepEventPayload.EventTimestamp"/> is
/// included it is the moment of revocation.
/// </summary>
public sealed record SessionRevokedPayload : CaepEventPayload;
