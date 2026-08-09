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
