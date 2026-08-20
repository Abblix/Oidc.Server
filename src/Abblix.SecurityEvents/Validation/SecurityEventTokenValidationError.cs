// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.SecurityEvents.Validation;

/// <summary>
/// A validation failure: the code a receiver branches on, and the sentence a log reader needs.
/// </summary>
/// <param name="Code">The failure class.</param>
/// <param name="Description">What exactly failed, in the words of the step that found it.</param>
public record SecurityEventTokenValidationError(SecurityEventTokenErrorCode Code, string Description)
{
    /// <summary>
    /// Returns the description - the half of the error a human reads.
    /// </summary>
    public override string ToString() => Description;
}
