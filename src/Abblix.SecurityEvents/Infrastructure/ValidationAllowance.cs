// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.SecurityEvents.Infrastructure;

/// <summary>
/// One acknowledged departure: the security-critical default a profile does not carry, and why.
/// </summary>
/// <param name="Step">The step this excuses, and only this step.</param>
/// <param name="Reason">Why this profile is right not to carry it.</param>
internal sealed record ValidationAllowance(Type Step, string Reason);
