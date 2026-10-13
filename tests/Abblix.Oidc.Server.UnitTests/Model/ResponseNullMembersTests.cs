// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Model;

/// <summary>
/// A response this library writes leaves out the members it has no value for, whatever JSON options the host
/// configured: the omission is declared on the members themselves, so the host's options carry nothing of the
/// library's and no setting the library would otherwise have to make on them.
/// </summary>
public class ResponseNullMembersTests
{
    public static TheoryData<Type> Responses() =>
    [
        typeof(ClientRegistrationResponse),
        typeof(ConfigurationResponse),
        typeof(MtlsAliases),
        typeof(ReadClientSuccessfulResponse),
        typeof(RegisteredClientMetadata),
    ];

    [Theory]
    [MemberData(nameof(Responses))]
    public void AMemberWithNoValueIsLeftOutUnderPlainOptions(Type response)
    {
        var empty = RuntimeHelpers.GetUninitializedObject(response);

        var written = JsonNode.Parse(JsonSerializer.Serialize(empty, response, new JsonSerializerOptions()))!.AsObject();

        Assert.DoesNotContain(written, member => member.Value is null);
    }
}
