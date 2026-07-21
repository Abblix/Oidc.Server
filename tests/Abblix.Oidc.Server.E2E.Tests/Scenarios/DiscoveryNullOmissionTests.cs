// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Text.Json;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// Proves that the discovery document omits what the provider does not have, rather than publishing it as null.
/// </summary>
/// <remarks>
/// The two are not interchangeable to a reader. OpenID Connect Discovery and RFC 8414 describe optional members
/// as absent when they do not apply, and a client decides what a provider supports by asking whether a member is
/// there. A member published as <c>null</c> is present, so a client that checks for presence concludes the
/// capability exists and then fails at the moment it tries to use it - a fault that surfaces far from its cause.
///
/// The omission is not a property of the model but of one line in each adapter's formatter, a serializer modifier
/// that a later refactoring of how those options are built would drop without any compiler complaint. Asserting
/// it on the wire is the only place the guarantee actually lives.
/// </remarks>
public class DiscoveryNullOmissionTests(TestFactory factory) : TestBase(factory)
{
    [Theory]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/oauth-authorization-server")]
    public async Task The_discovery_document_publishes_no_null_members(string path)
    {
        var client = CreateClient();

        var json = await client.GetStringAsync(path, TestContext.Current.CancellationToken);
        using var document = JsonDocument.Parse(json);

        var nullMembers = new List<string>();
        CollectNullMembers(document.RootElement, string.Empty, nullMembers);

        Assert.True(
            nullMembers.Count == 0,
            $"The document at '{path}' publishes null for: {string.Join(", ", nullMembers)}. "
            + "An optional member the provider does not have must be absent, not null.");
    }

    /// <summary>
    /// Walks the whole document rather than its top level, because a null nested inside a published object
    /// misleads a reader exactly as much as one at the root.
    /// </summary>
    private static void CollectNullMembers(JsonElement element, string path, List<string> nullMembers)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Null:
                nullMembers.Add(path.Length == 0 ? "<root>" : path);
                break;

            case JsonValueKind.Object:
                foreach (var member in element.EnumerateObject())
                    CollectNullMembers(member.Value, path.Length == 0 ? member.Name : $"{path}.{member.Name}", nullMembers);
                break;

            case JsonValueKind.Array:
                var index = 0;
                foreach (var item in element.EnumerateArray())
                    CollectNullMembers(item, $"{path}[{index++}]", nullMembers);
                break;

            case JsonValueKind.Undefined:
            case JsonValueKind.String:
            case JsonValueKind.Number:
            case JsonValueKind.True:
            case JsonValueKind.False:
                break;

            default:
                throw new InvalidOperationException($"Unhandled JSON value kind '{element.ValueKind}' at '{path}'.");
        }
    }
}
