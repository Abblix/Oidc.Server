// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SecurityEvents.Delivery;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// What one push delivery pass has achieved so far, handed to each transmission in turn
/// (Collecting Parameter): the per-item step records its outcome here, and the pass reads the
/// totals once it ends.
/// </summary>
internal sealed class PushDeliveryTally
{
    /// <summary>SETs the receiver accepted and the queue released.</summary>
    public int Delivered { get; private set; }

    /// <summary>SETs the receiver judged invalid, dropped from the queue as terminal.</summary>
    public int Rejected { get; private set; }

    /// <summary>
    /// The first refusal of the pass, kept so the summary can name a reason. Per-SET logging is what
    /// the queue's own shape rules out: it is read whole, so a receiver that refuses a backlog would
    /// write one line per event - thousands in one pass, differing only in the identifier.
    /// </summary>
    public DeliveryError? FirstRefusal { get; private set; }

    public void RecordDelivered() => Delivered++;

    public void RecordRejected(DeliveryError refusal)
    {
        FirstRefusal ??= refusal;
        Rejected++;
    }

    public PushDeliveryPassOutcome ToOutcome() => new(Delivered, Rejected);
}
