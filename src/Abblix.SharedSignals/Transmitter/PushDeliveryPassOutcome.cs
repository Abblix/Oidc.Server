// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// What one push delivery pass achieved.
/// </summary>
/// <param name="Delivered">SETs the receiver accepted and the queue released.</param>
/// <param name="Rejected">SETs the receiver judged invalid, dropped from the queue as terminal
/// (RFC 8935 Section 2.3).</param>
public sealed record PushDeliveryPassOutcome(int Delivered, int Rejected);