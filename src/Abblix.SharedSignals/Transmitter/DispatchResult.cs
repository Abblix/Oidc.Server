// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// What one dispatch of an event did: how many streams now hold it, and which streams it was meant for but could
/// not be put into.
/// </summary>
/// <param name="Reached">
/// How many streams the event was enqueued for. Zero with nothing in <paramref name="NotReached"/> is an event no
/// stream takes, which is a normal outcome.
/// </param>
/// <param name="NotReached">
/// The streams the dispatch failed on - the outbox refused the event, the token could not be built, the sharing
/// policy or the stream store failed. Pass them to
/// <see cref="EventDispatcher.DispatchAsync(SecurityEventDescriptor,IEnumerable{StreamReference},CancellationToken)"/>
/// to try them again without sending the event a second time to the streams that already hold it.
/// </param>
public sealed record DispatchResult(int Reached, IReadOnlyList<StreamReference> NotReached);
