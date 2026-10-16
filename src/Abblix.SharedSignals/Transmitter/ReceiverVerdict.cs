// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net.Http.Json;
using System.Text.Json;
using Abblix.SecurityEvents.Delivery;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// The receiver's verdict on a push delivery it refused with a 400.
/// </summary>
internal static class ReceiverVerdict
{
    /// <summary>How much of the receiver's description is carried into the log.</summary>
    /// <remarks>
    /// The field is the receiver's to fill and RFC 8935 Section 2.3 puts no bound on it - "the exact content
    /// of this field is implementation specific" - so it arrives as text of any length from a party this
    /// deployment does not control. A diagnostic that does not fit in this much is not a diagnostic.
    /// </remarks>
    private const int DescriptionBudget = 256;

    /// <summary>The receiver's own words, bounded and stripped of anything that could forge a log line.</summary>
    /// <remarks>
    /// Control characters go first. A plain-text sink writes a newline as a newline, so a receiver could
    /// otherwise put a whole fabricated entry into this deployment's log through a field it fills itself -
    /// and the escapes that clear a terminal or rewrite its title ride the same path.
    /// </remarks>
    public static string Readable(string? description)
    {
        if (string.IsNullOrEmpty(description))
        {
            return "(none)";
        }

        var kept = description.Length <= DescriptionBudget ? description : description[..DescriptionBudget];
        var text = new string([.. kept.Select(character => char.IsControl(character) ? ' ' : character)]);
        return description.Length <= DescriptionBudget ? text : text + "...";
    }

    /// <summary>
    /// Reads the error body a receiver owes with a 400 (RFC 8935 Section 2.3).
    /// </summary>
    /// <remarks>
    /// A body that is missing, malformed or of another media type yields null, which the caller treats as final.
    /// The alternative, treating an unreadable verdict as transient, would let a receiver answering 400 with an
    /// HTML error page hold the head of the queue for as long as it kept doing so.
    /// </remarks>
    public static async Task<DeliveryError?> ReadAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        try
        {
            return await response.Content.ReadFromJsonAsync<DeliveryError>(cancellationToken);
        }
        catch (Exception exception) when (exception is JsonException or NotSupportedException or HttpRequestException)
        {
            return null;
        }
    }
}
