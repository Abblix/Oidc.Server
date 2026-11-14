// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json;
using Abblix.Utils.Json;

namespace Abblix.Utils.UnitTests.Json;

/// <summary>
/// Holds <see cref="ElementValueTokens"/> complete: every reader token is either handed to the element converter
/// or named here as one the array converter answers on its own, so a token added to the reader fails this test
/// until somebody decides which side it belongs to.
/// </summary>
public class ElementValueTokensTests
{
    private static readonly JsonTokenType[] TokensAnsweredByArrayConverter =
    [
        JsonTokenType.None,
        JsonTokenType.EndObject,
        JsonTokenType.EndArray,
        JsonTokenType.PropertyName,
        JsonTokenType.Comment,
        JsonTokenType.Null,
    ];

    public static TheoryData<JsonTokenType> AllTokens => new(Enum.GetValues<JsonTokenType>());

    [Theory]
    [MemberData(nameof(AllTokens))]
    public void EveryToken_IsClassified(JsonTokenType token)
        => Assert.NotEqual(ElementValueTokens.Opens(token), TokensAnsweredByArrayConverter.Contains(token));
}
