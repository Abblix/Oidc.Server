// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Utils;

/// <summary>
/// Marks a type whose values arrive from outside the server - a request, a token header or payload - so a log
/// record carries them only as <see cref="Sanitized"/>.
/// </summary>
/// <remarks>
/// A sender chooses every character of such a value, a line break that starts a forged record included. The Abblix
/// analyzers refuse a logging call that passes a value read from a marked type, or the marked type itself, other than
/// as a sanitized value or a fingerprint.
/// </remarks>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct, Inherited = false)]
public sealed class ExternalInputAttribute : Attribute;
