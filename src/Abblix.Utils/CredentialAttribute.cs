// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Utils;

/// <summary>
/// Marks a value that grants access by itself - a code, a token, a secret - so a log record carries it only as its
/// <see cref="Fingerprint"/>.
/// </summary>
/// <remarks>
/// A log is read by more people than the store the value lives in, and a sanitized copy of a credential still opens
/// what the credential opens. The Abblix analyzers refuse a logging call that passes a value read from a marked
/// member other than as a fingerprint.
/// </remarks>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public sealed class CredentialAttribute : Attribute;
