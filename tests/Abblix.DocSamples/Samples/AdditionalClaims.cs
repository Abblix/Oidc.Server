// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.DocSamples.Samples;

/// <summary>
/// The compiled copy of the sample documenting what a host may hang off an authentication session.
/// </summary>
/// <remarks>
/// The sample is an object-initializer fragment, so the wrapper is the object it initialises. It goes
/// LAST in the initializer, because the fragment carries no trailing comma of its own and adding one
/// here would put a character in the compiled copy that the documentation does not have.
/// </remarks>
internal static class AdditionalClaimsSample
{
    internal static AuthSession Build() => new(
        "user-1", "session-1", DateTimeOffset.UtcNow, "https://idp.example.com")
    {
        // <sample>
        AdditionalClaims = new JsonObject
        {
            ["tenant_id"] = "tenant-123",                          // string
            ["roles"] = new JsonArray("admin", "user"),            // array
            ["permissions"] = new JsonArray("read", "write"),      // array
            ["is_verified"] = true,                                // boolean
            ["login_count"] = 42,                                  // number
            ["metadata"] = new JsonObject                          // nested object
            {
                ["department"] = "Engineering",
                ["manager"] = "john@example.com"
            }
        }
        // </sample>
    };
}
