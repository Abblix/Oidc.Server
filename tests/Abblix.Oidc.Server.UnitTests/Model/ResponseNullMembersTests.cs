// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Abblix.Oidc.Server.Model;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Model;

/// <summary>
/// A response this library writes leaves out the members it has no value for, whatever JSON options the host
/// configured: the omission is declared on the model itself, so the host's options carry nothing of the library's.
/// </summary>
/// <remarks>
/// On .NET 11 the omission is one attribute on the type; .NET 10's serializer refuses an attribute there, so on
/// .NET 10 each member carries its own, and a member added later without one is written as null on .NET 10 alone.
/// This suite runs on both frameworks and checks every member of every model that declares the omission.
/// The models are found from their declarations rather than from a list: on .NET 10 the type-level attribute is
/// compiled out, so the assembly cannot say which models declare it, while the source declares it for both.
/// </remarks>
public class ResponseNullMembersTests
{
    private const string NetElevenSymbol = "NET11_0_OR_GREATER";

    private static readonly Lazy<IReadOnlyList<Type>> Declared = new(FindDeclared);

    public static TheoryData<Type, string> ResponsesUnderEachOptions()
    {
        var data = new TheoryData<Type, string>();
        foreach (var response in Declared.Value)
        {
            foreach (var options in Options.Keys)
                data.Add(response, options);
        }
        return data;
    }

    /// <summary>
    /// The options a response is written with: the serializer's own defaults, which the CIBA push notification and
    /// signed metadata use, and the web defaults ASP.NET Core gives a host that sets nothing.
    /// </summary>
    private static readonly IReadOnlyDictionary<string, JsonSerializerOptions> Options =
        new Dictionary<string, JsonSerializerOptions>
        {
            ["serializer defaults"] = new(),
            ["web defaults"] = new(JsonSerializerDefaults.Web),
        };

    /// <summary>
    /// The walk reaches the declarations: a walk that found nothing, or missed a model known to declare the omission,
    /// would leave the theory below with nothing to fail on.
    /// </summary>
    [Fact]
    public void TheWalkFindsTheModelsDeclaringTheOmission()
    {
        Assert.Contains(typeof(TokenResponse), Declared.Value);
        Assert.Contains(typeof(ConfigurationResponse), Declared.Value);
    }

    [Theory]
    [MemberData(nameof(ResponsesUnderEachOptions))]
    public void EveryMemberWithNoValueIsLeftOut(Type response, string options)
    {
        var empty = RuntimeHelpers.GetUninitializedObject(response);
        var written = JsonNode.Parse(JsonSerializer.Serialize(empty, response, Options[options]))!.AsObject();

        var absent = response.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(property => (property, name: property.GetCustomAttribute<JsonPropertyNameAttribute>()?.Name))
            .Where(member => member.name is not null && member.property.GetValue(empty) is null)
            .Select(member => member.name!)
            .ToArray();

        Assert.NotEmpty(absent);
        Assert.All(absent, name => Assert.False(written.ContainsKey(name), $"{response.Name} writes {name} as null"));
    }

    private static IReadOnlyList<Type> FindDeclared()
    {
        var root = RepositoryRoot();
        var library = typeof(TokenResponse).Assembly;
        var parseOptions = CSharpParseOptions.Default.WithPreprocessorSymbols(NetElevenSymbol);
        var excluded = new[] { "obj", "bin" };

        return Directory
            .EnumerateFiles(Path.Combine(root, "src", library.GetName().Name!), "*.cs", SearchOption.AllDirectories)
            .Where(path => !Path.GetRelativePath(root, path).Split(Path.DirectorySeparatorChar).Intersect(excluded).Any())
            .SelectMany(path => CSharpSyntaxTree.ParseText(File.ReadAllText(path), parseOptions)
                .GetRoot().DescendantNodes().OfType<TypeDeclarationSyntax>())
            .Where(DeclaresTheOmission)
            .Select(declaration => library.GetType(FullName(declaration), throwOnError: true)!)
            .ToArray();
    }

    private static bool DeclaresTheOmission(TypeDeclarationSyntax declaration)
        => declaration.AttributeLists.SelectMany(list => list.Attributes).Any(attribute =>
            SimpleName(attribute.Name) is "JsonIgnore" or nameof(JsonIgnoreAttribute)
            && attribute.ArgumentList?.Arguments.Any(argument =>
                argument.NameEquals?.Name.Identifier.Text == nameof(JsonIgnoreAttribute.Condition)
                && argument.Expression is MemberAccessExpressionSyntax
                {
                    Name.Identifier.Text: nameof(JsonIgnoreCondition.WhenWritingNull),
                }) == true);

    private static string SimpleName(NameSyntax name) => name switch
    {
        QualifiedNameSyntax qualified => qualified.Right.Identifier.Text,
        AliasQualifiedNameSyntax aliased => aliased.Name.Identifier.Text,
        SimpleNameSyntax simple => simple.Identifier.Text,
        _ => throw new ArgumentOutOfRangeException(nameof(name), name.Kind(), null),
    };

    private static string FullName(TypeDeclarationSyntax declaration)
    {
        var types = declaration.AncestorsAndSelf().OfType<BaseTypeDeclarationSyntax>().Select(type => type.Identifier.Text)
            .Reverse();
        var namespaces = declaration.Ancestors().OfType<BaseNamespaceDeclarationSyntax>().Select(ns => ns.Name.ToString())
            .Reverse();
        return string.Join('.', namespaces) + "." + string.Join('+', types);
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Abblix.Oidc.slnx")))
            directory = directory.Parent;

        Assert.NotNull(directory);
        return directory.FullName;
    }
}
