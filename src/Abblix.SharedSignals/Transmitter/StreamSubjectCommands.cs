// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SecurityEvents.Subjects;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// The changes the Add Subject and Remove Subject operations make to a stream (SSF 1.0
/// Sections 8.1.3.2-8.1.3.3), each a Command the management service's read-modify-write loop
/// applies to whatever version of the stream it reads, as often as a contended write needs.
/// </summary>
internal static class StreamSubjectCommands
{
    /// <summary>
    /// Whether a subject is a Complex Subject naming no member, which SSF 1.0 Section 3.3 forbids and
    /// which, added to a stream, would match every event on it.
    /// </summary>
    /// <param name="subject">The subject a receiver asked to add.</param>
    public static bool NamesNothing(SubjectIdentifier subject) => subject is ComplexSubject { HasMembers: false };

    /// <summary>
    /// Adds a subject, replacing an identical one already added.
    /// </summary>
    /// <param name="subject">The subject the receiver added.</param>
    /// <param name="verified">Whether the receiver vouches for it (Section 8.1.3.2).</param>
    public static Func<StreamState, StreamState> Add(SubjectIdentifier subject, bool verified)
    {
        var added = new StreamSubject(subject, verified);
        return stream => stream with
        {
            AddedSubjects =
            [
                .. stream.AddedSubjects.Where(existing => !SubjectMatcher.Identical(existing.Subject, subject)),
                added,
            ],
            // Under ALL, an addition undoes an earlier removal; under NONE the removal list is
            // inert, and dropping a stale entry there costs nothing.
            RemovedSubjects =
            [
                .. stream.RemovedSubjects.Where(removed => !SubjectMatcher.Identical(removed, subject)),
            ],
        };
    }

    /// <summary>
    /// Removes a subject: drops it from the added ones and, under ALL, records it as removed.
    /// </summary>
    /// <param name="subject">The subject the receiver removed.</param>
    public static Func<StreamState, StreamState> Remove(SubjectIdentifier subject)
        => stream => stream with
        {
            AddedSubjects =
            [
                .. stream.AddedSubjects.Where(added => !SubjectMatcher.Identical(added.Subject, subject)),
            ],
            RemovedSubjects = stream.SubjectsMode switch
            {
                // Under ALL a removal carves the subject out of the default coverage.
                StreamSubjectsMode.All when !stream.RemovedSubjects.Any(
                        removed => SubjectMatcher.Identical(removed, subject)) =>
                    [.. stream.RemovedSubjects, subject],
                StreamSubjectsMode.All or StreamSubjectsMode.None => stream.RemovedSubjects,
                _ => throw new ArgumentOutOfRangeException(
                    nameof(stream), stream.SubjectsMode, "A subjects mode without a removal rule."),
            },
        };
}
