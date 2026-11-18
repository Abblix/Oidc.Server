// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Tests.Shared;

/// <summary>
/// How a host registers a service of its own relative to the library's registration.
/// </summary>
public enum HostRegistration
{
    /// <summary>Added before the library is registered.</summary>
    AddBefore,

    /// <summary>Added after the library is registered.</summary>
    AddAfter,

    /// <summary>Added after the library is registered, only if no registration of the type exists yet.</summary>
    TryAddAfter,
}
