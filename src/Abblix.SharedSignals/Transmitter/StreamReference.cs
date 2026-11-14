// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// Names one stream of one receiver. A stream identifier is unique only within its receiver, so the pair is what
/// <see cref="IStreamStore"/> finds a stream by.
/// </summary>
/// <param name="ReceiverId">The receiver the stream belongs to.</param>
/// <param name="StreamId">The stream's identifier.</param>
public sealed record StreamReference(string ReceiverId, string StreamId);
