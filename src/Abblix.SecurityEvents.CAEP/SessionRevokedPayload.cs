// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.SecurityEvents.CAEP;

/// <summary>
/// Session Revoked (CAEP 1.0 Section 3.1): the session identified by the subject has been
/// revoked. The event carries no claims of its own - the subject names the session, directly
/// or through the properties of a complex subject, in which case the revocation applies to any
/// session matching the combined claims; when <see cref="CaepEventPayload.EventTimestamp"/> is
/// included it is the moment of revocation.
/// </summary>
public sealed record SessionRevokedPayload : CaepEventPayload;
