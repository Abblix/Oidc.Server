// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.SecurityEvents.Events;

namespace Abblix.SecurityEvents.RISC;

/// <summary>
/// Account Credential Change Required (RISC 1.0 Section 2.1): the account identified by the
/// subject was required to change a credential - a forced password change, for instance. The
/// event carries no attributes.
/// </summary>
public sealed record AccountCredentialChangeRequiredPayload : IEventPayload;
