// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

/// <summary>
/// Represents the internal result of a successful client deletion operation.
/// </summary>
/// <remarks>
/// <para>
/// <strong>IMPORTANT:</strong> Per RFC 7592 Section 2.3, a successful DELETE request to the client
/// configuration endpoint MUST return HTTP 204 No Content with an empty response body.
/// </para>
/// <para>
/// This record is used internally to track deletion details but should NOT be serialized in the HTTP response.
/// The HTTP response must be 204 No Content with headers:
/// <list type="bullet">
/// <item><c>Cache-Control: no-store</c></item>
/// <item><c>Pragma: no-cache</c></item>
/// </list>
/// </para>
/// <para>
/// A successful deletion invalidates:
/// <list type="bullet">
/// <item>The client's client_id</item>
/// <item>The client's client_secret</item>
/// <item>The registration_access_token</item>
/// <item>All existing authorization grants and tokens (access tokens, refresh tokens, etc.)</item>
/// </list>
/// </para>
/// </remarks>
/// <param name="ClientId">The unique identifier of the client that was removed.</param>
/// <param name="RemovedAt">The timestamp when the client was removed from the system.</param>
public record RemoveClientSuccessfulResponse(
    string ClientId,
    DateTimeOffset RemovedAt);
