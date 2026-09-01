// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// What one push delivery pass achieved.
/// </summary>
/// <param name="Delivered">SETs the receiver accepted and the queue released.</param>
/// <param name="Rejected">SETs the receiver judged invalid, dropped from the queue as terminal
/// (RFC 8935 Section 2.3).</param>
public sealed record PushDeliveryPassOutcome(int Delivered, int Rejected);