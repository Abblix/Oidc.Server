// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.SecurityEvents.Infrastructure;

/// <summary>
/// A step the validation profile may not quietly lose, declared by whichever package contributes it.
/// </summary>
/// <remarks>
/// The declaration lives beside the registration that adds the step, so the two cannot drift: a package that
/// stops contributing a step stops declaring it in the same edit. Read as a set, the declarations are what
/// <see cref="InsecureValidationGuard"/> holds the composed profile to - which is how
/// <see cref="Validation.ISecurityCriticalValidator"/> keeps the promise its own documentation makes for every
/// step that carries it, rather than only for the ones this package happens to ship.
/// </remarks>
/// <param name="StepType">The step's implementation type, as it appears among the family's members.</param>
internal sealed record CriticalValidationStep(Type StepType);
