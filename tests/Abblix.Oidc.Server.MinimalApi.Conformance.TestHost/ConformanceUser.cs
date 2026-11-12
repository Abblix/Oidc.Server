// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Features.UserInfo;

namespace Abblix.Oidc.Server.MinimalApi.Conformance.TestHost;

/// <summary>
/// The one end user the conformance suite signs in as, carrying every standard claim, since the suite's
/// scope and claims tests ask for each of the profile, email, address and phone groups and fail on a missing one.
/// </summary>
/// <param name="email">The address the suite's browser types into the sign-in form.</param>
/// <param name="secret">The value it types into the password field.</param>
public sealed class ConformanceUser(string email, string secret) : IUserInfoProvider
{
    public const string Subject = "conformance-user";

    private JsonObject AllClaims() => new()
    {
        ["sub"] = Subject,
        ["name"] = "Conformance User",
        ["given_name"] = "Conformance",
        ["family_name"] = "User",
        ["middle_name"] = "Suite",
        ["nickname"] = "conformance",
        ["preferred_username"] = "conformance",
        ["profile"] = "https://example.com/conformance",
        ["picture"] = "https://example.com/conformance.png",
        ["website"] = "https://example.com",
        ["gender"] = "unspecified",
        ["birthdate"] = "2000-01-01",
        ["zoneinfo"] = "Europe/London",
        ["locale"] = "en-GB",
        ["updated_at"] = 1735689600,
        ["email"] = email,
        ["email_verified"] = true,
        ["address"] = new JsonObject
        {
            ["formatted"] = "1 Example Street, London, SW1A 1AA, GB",
            ["street_address"] = "1 Example Street",
            ["locality"] = "London",
            ["postal_code"] = "SW1A 1AA",
            ["country"] = "GB",
        },
        ["phone_number"] = "+44 20 7946 0000",
        ["phone_number_verified"] = true,
    };

    public bool Matches(string typedEmail, string typedSecret)
        => string.Equals(typedEmail, email, StringComparison.OrdinalIgnoreCase) && typedSecret == secret;

    public Task<JsonObject?> GetUserInfoAsync(
        TenantDefinition tenant, AuthSession authSession, IEnumerable<string> requestedClaims)
    {
        if (authSession.Subject != Subject)
            return Task.FromResult<JsonObject?>(null);

        var all = AllClaims();
        var result = new JsonObject();
        foreach (var claim in requestedClaims.Distinct())
        {
            if (all.TryGetPropertyValue(claim, out var value))
                result[claim] = value?.DeepClone();
        }

        return Task.FromResult<JsonObject?>(result);
    }
}
