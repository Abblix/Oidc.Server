// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.SecurityEvents.Infrastructure;

/// <summary>
/// What the <see cref="InsecureValidationGuard"/> needs to know about the profile it decorates:
/// which family to read and which allowances excuse a missing critical step.
/// </summary>
/// <param name="Key">The profile's service key.</param>
/// <param name="Allowances">The profile's own allowances - the only ones that can excuse it.</param>
internal sealed record ValidationProfileIdentity(object Key, IReadOnlyList<ValidationAllowance> Allowances);
