// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;

/// <summary>
/// Reads the error code an error response carries in its JSON body (RFC 6749 section 5.2), so a test compares the
/// code itself rather than looking for it as text, which the description could also contain.
/// </summary>
public static class ErrorResponseReader
{
    /// <summary>
    /// The <c>error</c> member of the response's JSON body.
    /// </summary>
    /// <param name="response">The response to read.</param>
    public static async Task<string?> ErrorCodeOf(HttpResponseMessage response)
    {
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        return JsonNode.Parse(body)?[ErrorResponse.Parameters.Error]?.GetValue<string>();
    }
}
