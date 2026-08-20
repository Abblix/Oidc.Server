// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Net;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// What one management operation earned: the status code the specification assigns the outcome
/// (SSF 1.0 Section 8.1's error tables), the body a successful read or update carries, and -
/// for the operator's logs, never the wire, since the management API defines no error body -
/// why a refusal refused.
/// </summary>
/// <typeparam name="TBody">The body of a successful outcome.</typeparam>
/// <param name="StatusCode">The status code the transport answers with.</param>
/// <param name="Body">The response body; null for outcomes whose response is empty.</param>
/// <param name="Description">Why a refusal refused; null on success.</param>
public sealed record ManagementResult<TBody>(
    HttpStatusCode StatusCode,
    TBody? Body = default,
    string? Description = null)
{
    /// <summary>A successful read or update: "200 OK" with the body.</summary>
    public static ManagementResult<TBody> Ok(TBody body) => new(HttpStatusCode.OK, body);

    /// <summary>A successful operation answered "200 OK" with an empty body - the add-subject
    /// shape (SSF 1.0 Section 8.1.3.2).</summary>
    public static ManagementResult<TBody> Ok() => new(HttpStatusCode.OK);

    /// <summary>A successful creation: "201 Created" with the created document.</summary>
    public static ManagementResult<TBody> Created(TBody body) => new(HttpStatusCode.Created, body);

    /// <summary>A successful operation whose response is empty: "204 No Content".</summary>
    public static ManagementResult<TBody> NoContent() => new(HttpStatusCode.NoContent);

    /// <summary>No stream with the given identifier for this receiver: "404 Not Found".</summary>
    public static ManagementResult<TBody> NotFound(string description)
        => new(HttpStatusCode.NotFound, default, description);

    /// <summary>
    /// The stream already exists and the transmitter allows one per receiver: "409 Conflict".
    /// </summary>
    /// <remarks>
    /// Creation only. SSF 1.0 gives this code exactly one meaning, in the Create Stream error table
    /// of Section 8.1.1.1, and the update tables of Sections 8.1.1.3 and 8.1.2.2 do not list it at
    /// all - so answering an update with it says "you already have a stream" to a receiver reading
    /// the specification, which is the opposite of what a failed update means.
    /// </remarks>
    public static ManagementResult<TBody> Conflict(string description)
        => new(HttpStatusCode.Conflict, default, description);

    /// <summary>
    /// The update was taken and not carried out: "202 Accepted".
    /// </summary>
    /// <remarks>
    /// The code SSF 1.0 assigns to exactly this outcome in both update tables - "accepted, but not
    /// processed. Receiver MAY try the same request later to get processing result" - and Section
    /// 8.1.2.2 states it as a MUST for a transmitter that cannot decide whether to complete the
    /// request. It tells the receiver the one thing that matters here and that no other code does:
    /// nothing changed, and repeating the call is the way forward rather than a mistake.
    /// </remarks>
    public static ManagementResult<TBody> Accepted(string description)
        => new(HttpStatusCode.Accepted, default, description);

    /// <summary>The request is invalid: "400 Bad Request".</summary>
    public static ManagementResult<TBody> BadRequest(string description)
        => new(HttpStatusCode.BadRequest, default, description);

    /// <summary>The receiver asks too often: "429 Too Many Requests"
    /// (SSF 1.0 Section 8.1.4.2).</summary>
    public static ManagementResult<TBody> TooManyRequests(string description)
        => new(HttpStatusCode.TooManyRequests, default, description);
}
