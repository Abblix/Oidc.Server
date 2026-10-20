// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Xunit;

namespace Abblix.Analyzers.UnitTests;

/// <summary>
/// A type handed to the entity storage without a protobuf codec is refused, and so is a member a codec's mapper
/// leaves out of either direction, while a complete mapping and the marked exceptions pass.
/// </summary>
public class StoredTypeAnalyzerTests
{
    /// <summary>
    /// The storage, the codec, the marks and a message interface, declared as the server declares them.
    /// </summary>
    private const string Infrastructure = """
        using System;
        using System.Threading.Tasks;

        namespace Google.Protobuf
        {
            public interface IMessage { }
        }

        namespace Abblix.Oidc.Server.Features.Storages
        {
            using Google.Protobuf;

            public interface IEntityStorage
            {
                Task SetAsync<T>(string key, T value);
                Task<T?> GetAsync<T>(string key);
                Task<bool> TrySetIfAbsentAsync<T>(string key, T value);
            }

            public sealed class ProtobufCodec<TValue>(Func<TValue, byte[]> toBytes, Func<byte[], TValue> fromBytes);

            public static class ProtobufCodecs
            {
                public static ProtobufCodec<TValue> Mapped<TValue, TMessage>(
                    Func<TValue, TMessage> toProto, Func<TMessage, TValue> fromProto)
                    where TMessage : IMessage
                    => new(_ => [], _ => default!);

                public static ProtobufCodec<TMessage> Stored<TMessage>() where TMessage : IMessage
                    => Mapped<TMessage, TMessage>(message => message, message => message);
            }

            public sealed class StoredAsJsonAttribute(string reason) : Attribute;

            public sealed class CodecRegistryAttribute : Attribute;

            public sealed class NotStoredAttribute(string reason) : Attribute;
        }

        namespace Sample
        {
            using Abblix.Oidc.Server.Features.Storages;
            using Google.Protobuf;

            public sealed class GrantMessage : IMessage
            {
                public const int SubjectFieldNumber = 1;
                public string Subject { get; set; } = "";

                public const int ScopeFieldNumber = 2;
                public string Scope { get; set; } = "";
                public bool HasScope => Scope.Length > 0;
            }

            public record Grant(string Subject)
            {
                public string? Scope { get; init; }
                public bool Scoped => Scope != null;
            }
        }
        """;

    private const string CompleteMapper = """
        namespace Sample
        {
            public static class GrantMapper
            {
                public static GrantMessage ToProto(this Grant grant)
                    => new() { Subject = grant.Subject, Scope = grant.Scope ?? "" };

                public static Grant FromProto(this GrantMessage message)
                    => new(message.Subject) { Scope = message.HasScope ? message.Scope : null };
            }
        }
        """;

    private static readonly string Registry = RegistryReading();

    /// <summary>
    /// The serializer's codecs: the codec of <c>Grant</c>, and the codecs of each registry field named, read the way
    /// the server's serializer reads its registries.
    /// </summary>
    private static string RegistryReading(params string[] fields) => $$"""
        namespace Sample
        {
            using Abblix.Oidc.Server.Features.Storages;

            public static class Codecs
            {
                [Abblix.Oidc.Server.Features.Storages.CodecRegistry]
                public static readonly object[] All =
                [
                    ProtobufCodecs.Mapped((Grant grant) => grant.ToProto(), message => message.FromProto()),
                    {{string.Concat(fields.Select(field => $".. {field}, "))}}
                ];
            }
        }
        """;

    private static Task<ImmutableArray<Diagnostic>> DiagnosticsOf(params string[] sources)
    {
        (string Path, string Source)[] files =
        [
            ("Infrastructure.cs", Infrastructure),
            .. sources.Select((source, index) => ($"Sample{index}.cs", source)),
        ];
        return AnalyzerRun.DiagnosticsOf(new StoredTypeAnalyzer(), files);
    }

    private static string Storing(string body) => $$"""
        namespace Sample
        {
            using System.Threading.Tasks;
            using Abblix.Oidc.Server.Features.Storages;

            public sealed class Store(IEntityStorage storage)
            {
                {{body}}
            }
        }
        """;

    private static IEnumerable<(string? Subject, string? Direction)> Reported(
        ImmutableArray<Diagnostic> diagnostics, DiagnosticDescriptor rule)
        => diagnostics
            .Where(diagnostic => diagnostic.Id == rule.Id)
            .Select(diagnostic => (
                diagnostic.Properties.GetValueOrDefault(StoredTypeAnalyzer.SubjectProperty),
                diagnostic.Properties.GetValueOrDefault(StoredTypeAnalyzer.DirectionProperty)))
            .Order();

    /// <summary>
    /// A type with a codec whose mapper carries every member both ways, written and read, raises nothing.
    /// </summary>
    [Fact]
    public async Task ACompleteMappingOfAStoredTypeIsAccepted()
    {
        var diagnostics = await DiagnosticsOf(CompleteMapper, Registry, Storing("""
            public Task Save(Grant grant) => storage.SetAsync("key", grant);
            public Task<Grant?> Load() => storage.GetAsync<Grant>("key");
            public Task<bool> Claim(Grant grant) => storage.TrySetIfAbsentAsync("key", grant);
            """));

        Assert.Empty(diagnostics);
    }

    [Theory]
    [InlineData("public Task Save(Note note) => storage.SetAsync(\"key\", note);")]
    [InlineData("public Task<Note?> Load() => storage.GetAsync<Note>(\"key\");")]
    [InlineData("public Task<bool> Claim(Note note) => storage.TrySetIfAbsentAsync(\"key\", note);")]
    public async Task ATypeWithNoCodecIsReportedAtTheCall(string call)
    {
        var diagnostics = await DiagnosticsOf(
            CompleteMapper,
            Registry,
            "namespace Sample { public sealed record Note(string Text); }",
            Storing(call));

        Assert.Equal([("Sample.Note", null)], Reported(diagnostics, StoredTypeAnalyzer.CodecRule));
    }

    [Fact]
    public async Task ATypeMarkedAsStoredAsJsonIsAccepted()
    {
        var diagnostics = await DiagnosticsOf(
            CompleteMapper,
            Registry,
            """
            namespace Sample
            {
                [Abblix.Oidc.Server.Features.Storages.StoredAsJson("read by an external tool")]
                public sealed record Note(string Text);
            }
            """,
            Storing("public Task Save(Note note) => storage.SetAsync(\"key\", note);"));

        Assert.Empty(diagnostics);
    }

    /// <summary>
    /// A helper passing a type parameter to the storage hides the type it stores from the rule, so only a storage
    /// wrapping another one may do it.
    /// </summary>
    [Fact]
    public async Task ACallForATypeParameterOutsideAStorageIsReported()
    {
        var diagnostics = await DiagnosticsOf(
            CompleteMapper,
            Registry,
            Storing("public Task Save<T>(T value) => storage.SetAsync(\"key\", value);"));

        Assert.Equal([("T", null)], Reported(diagnostics, StoredTypeAnalyzer.CodecRule));
    }

    /// <summary>
    /// A call made on a storage implementation rather than the interface is a storage call all the same.
    /// </summary>
    [Fact]
    public async Task ACallOnAStorageImplementationIsChecked()
    {
        var diagnostics = await DiagnosticsOf(CompleteMapper, Registry, """
            namespace Sample
            {
                using System.Threading.Tasks;
                using Abblix.Oidc.Server.Features.Storages;

                public sealed record Note(string Text);

                public sealed class Plain(IEntityStorage inner) : IEntityStorage
                {
                    public Task SetAsync<T>(string key, T value) => inner.SetAsync(key, value);
                    public Task<T?> GetAsync<T>(string key) => inner.GetAsync<T>(key);
                    public Task<bool> TrySetIfAbsentAsync<T>(string key, T value) => inner.TrySetIfAbsentAsync(key, value);
                }

                public sealed class Store(Plain storage)
                {
                    public Task<Note?> Load() => storage.GetAsync<Note>("key");
                }
            }
            """);

        Assert.Equal([("Sample.Note", null)], Reported(diagnostics, StoredTypeAnalyzer.CodecRule));
    }

    /// <summary>
    /// The serializer takes its codecs from the registry only, so a codec built anywhere else serves nothing.
    /// </summary>
    [Fact]
    public async Task ACodecBuiltOutsideTheRegistryDoesNotCount()
    {
        var diagnostics = await DiagnosticsOf(CompleteMapper, """
            namespace Sample
            {
                using Abblix.Oidc.Server.Features.Storages;

                public static class Elsewhere
                {
                    public static readonly object[] Unused =
                    [
                        ProtobufCodecs.Mapped((Grant grant) => grant.ToProto(), message => message.FromProto()),
                    ];
                }
            }
            """, Storing("public Task Save(Grant grant) => storage.SetAsync(\"key\", grant);"));

        Assert.Equal([("Sample.Grant", null)], Reported(diagnostics, StoredTypeAnalyzer.CodecRule));
    }

    /// <summary>
    /// A registry the serializer's own field reads counts, though it carries no mark itself.
    /// </summary>
    [Fact]
    public async Task ARegistryTheSerializerReadsCounts()
    {
        var diagnostics = await DiagnosticsOf(CompleteMapper, """
            namespace Sample
            {
                using System.Linq;
                using Abblix.Oidc.Server.Features.Storages;

                public static class Mapped
                {
                    public static readonly object[] All =
                    [
                        ProtobufCodecs.Mapped((Grant grant) => grant.ToProto(), message => message.FromProto()),
                    ];
                }

                public static class Serializer
                {
                    [CodecRegistry]
                    public static readonly object[] Codecs = Mapped.All.ToArray();
                }
            }
            """, Storing("public Task Save(Grant grant) => storage.SetAsync(\"key\", grant);"));

        Assert.Empty(diagnostics);
    }

    /// <summary>
    /// Only one field is the serializer's, so a second one marked as if it were is refused, rather than a registry
    /// nobody wired to the serializer being taken for one it reads.
    /// </summary>
    [Fact]
    public async Task ASecondMarkedFieldIsReported()
    {
        var diagnostics = await DiagnosticsOf(CompleteMapper, Registry, """
            namespace Sample
            {
                public static class Elsewhere
                {
                    [Abblix.Oidc.Server.Features.Storages.CodecRegistry]
                    public static readonly object[] All = [];
                }
            }
            """);

        Assert.Equal(
            [("Sample.Codecs.All", null), ("Sample.Elsewhere.All", null)],
            Reported(diagnostics, StoredTypeAnalyzer.RegistryRule));
    }

    /// <summary>
    /// A registry kept in an auto-property is read by the serializer as surely as one kept in a field.
    /// </summary>
    [Fact]
    public async Task ARegistryKeptInAnAutoPropertyCounts()
    {
        var diagnostics = await DiagnosticsOf(CompleteMapper, """
            namespace Sample
            {
                using System.Linq;
                using Abblix.Oidc.Server.Features.Storages;

                public static class Mapped
                {
                    public static object[] All { get; } =
                    [
                        ProtobufCodecs.Mapped((Grant grant) => grant.ToProto(), message => message.FromProto()),
                    ];
                }

                public static class Serializer
                {
                    [CodecRegistry]
                    public static readonly object[] Codecs = Mapped.All.ToArray();
                }
            }
            """, Storing("public Task Save(Grant grant) => storage.SetAsync(\"key\", grant);"));

        Assert.Empty(diagnostics);
    }

    /// <summary>
    /// A value computed from a constructor parameter is computed again by the type itself, so it is not owed a
    /// mapping, while the parameter handed on as it is still is.
    /// </summary>
    [Fact]
    public async Task APropertyComputedFromAParameterIsNotOwed()
    {
        var diagnostics = await DiagnosticsOf(RegistryReading("NoteCodecs.All"), CompleteMapper, """
            namespace Sample
            {
                public sealed class Note(string text)
                {
                    public string Text { get; } = text;
                    public int Length { get; } = text.Length;
                }

                public sealed class NoteMessage : Google.Protobuf.IMessage
                {
                    public const int TextFieldNumber = 1;
                    public string Text { get; set; } = "";
                }

                public static class NoteCodecs
                {
                    public static readonly object[] All =
                    [
                        Abblix.Oidc.Server.Features.Storages.ProtobufCodecs.Mapped(
                            (Note note) => new NoteMessage(),
                            message => new Note(message.Text)),
                    ];
                }
            }
            """);

        Assert.Equal(
            [("Sample.Note.Text", StoredTypeAnalyzer.ToMessage), ("Sample.NoteMessage.Text", StoredTypeAnalyzer.ToMessage)],
            Reported(diagnostics, StoredTypeAnalyzer.MappingRule));
    }

    /// <summary>
    /// A generic helper of a storage implementation hides the type it stores as well as any other helper, since only
    /// a member of the storage passes its caller's type on.
    /// </summary>
    [Fact]
    public async Task AGenericHelperOfAStorageImplementationIsReported()
    {
        var diagnostics = await DiagnosticsOf(CompleteMapper, Registry, """
            namespace Sample
            {
                using System;
                using System.Threading.Tasks;
                using Abblix.Oidc.Server.Features.Storages;

                public sealed class Wrapping(IEntityStorage inner) : IEntityStorage
                {
                    public Task SetAsync<T>(string key, T value) => inner.SetAsync(key, value);
                    public Task<T?> GetAsync<T>(string key) => inner.GetAsync<T>(key);
                    public Task<bool> TrySetIfAbsentAsync<T>(string key, T value) => inner.TrySetIfAbsentAsync(key, value);
                    public Task<Uri?> Probe(string key) => Load<Uri>(key);
                    private Task<TValue?> Load<TValue>(string key) => inner.GetAsync<TValue>(key);
                }
            }
            """);

        Assert.Equal([("TValue", null)], Reported(diagnostics, StoredTypeAnalyzer.CodecRule));
    }

    /// <summary>
    /// A codec of the registry counts however it is built there, with a factory or its constructor.
    /// </summary>
    [Fact]
    public async Task ACodecConstructedInTheRegistryCounts()
    {
        var diagnostics = await DiagnosticsOf("""
            namespace Sample
            {
                using Abblix.Oidc.Server.Features.Storages;

                public static class Codecs
                {
                    [CodecRegistry]
                    public static readonly object[] All =
                    [
                        new ProtobufCodec<string>(System.Text.Encoding.UTF8.GetBytes, System.Text.Encoding.UTF8.GetString),
                    ];
                }
            }
            """, Storing("public Task<string?> Load() => storage.GetAsync<string>(\"key\");"));

        Assert.Empty(diagnostics);
    }

    /// <summary>
    /// Another method of a type implementing the storage is not a storage call, generic as it may be.
    /// </summary>
    [Fact]
    public async Task AnotherGenericMethodOfAStorageImplementationIsNotAStorageCall()
    {
        var diagnostics = await DiagnosticsOf(CompleteMapper, Registry, """
            namespace Sample
            {
                using System.Threading.Tasks;
                using Abblix.Oidc.Server.Features.Storages;

                public sealed class Measured(IEntityStorage inner) : IEntityStorage
                {
                    public Task SetAsync<T>(string key, T value) => inner.SetAsync(key, value);
                    public Task<T?> GetAsync<T>(string key) => Measure(() => inner.GetAsync<T>(key));
                    public Task<bool> TrySetIfAbsentAsync<T>(string key, T value) => Measure(() => inner.TrySetIfAbsentAsync(key, value));
                    private static Task<TResult> Measure<TResult>(System.Func<Task<TResult>> call) => call();
                    public Task<bool> Probe() => Measure(() => Task.FromResult(true));
                }
            }
            """);

        Assert.Empty(diagnostics);
    }

    /// <summary>
    /// A written value is matched by its base type's codec, as the serializer matches it at run time, while a value
    /// read back is asked for by exactly the type named.
    /// </summary>
    [Fact]
    public async Task ADerivedTypeIsWrittenByItsBaseTypesCodecButNotReadBack()
    {
        var diagnostics = await DiagnosticsOf(
            CompleteMapper,
            """
            namespace Sample
            {
                using Abblix.Oidc.Server.Features.Storages;

                public class Base { public string? Value { get; set; } }
                public sealed class Derived : Base;

                public sealed class BaseMessage : Google.Protobuf.IMessage
                {
                    public const int ValueFieldNumber = 1;
                    public string Value { get; set; } = "";
                }

                public static class BaseMapper
                {
                    public static BaseMessage ToProto(Base value) => new() { Value = value.Value ?? "" };
                    public static Base FromProto(BaseMessage message) => new() { Value = message.Value };
                }

                public static class Codecs
                {
                    [Abblix.Oidc.Server.Features.Storages.CodecRegistry]
                    public static readonly object[] All =
                    [
                        ProtobufCodecs.Mapped((Base value) => BaseMapper.ToProto(value), BaseMapper.FromProto),
                    ];
                }
            }
            """,
            Storing("""
                public Task Save(Derived value) => storage.SetAsync("key", value);
                public Task<Derived?> Load() => storage.GetAsync<Derived>("key");
                """));

        Assert.Equal([("Sample.Derived", null)], Reported(diagnostics, StoredTypeAnalyzer.CodecRule));
    }

    /// <summary>
    /// A property a derived type adds is never written by its base type's codec, so writing the derived type that way
    /// owes the property a mark.
    /// </summary>
    [Fact]
    public async Task APropertyADerivedTypeAddsIsReportedWhenWrittenByTheBaseCodec()
    {
        var diagnostics = await DiagnosticsOf(
            CompleteMapper,
            Registry,
            """
            namespace Sample
            {
                public sealed record Extended(string Subject, string Lost) : Grant(Subject);
            }
            """,
            Storing("public Task Save(Extended value) => storage.SetAsync(\"key\", value);"));

        Assert.Equal([("Sample.Extended.Lost", StoredTypeAnalyzer.ToMessage)], Reported(diagnostics, StoredTypeAnalyzer.MappingRule));
    }

    /// <summary>
    /// A mapper that forgets a member on the way out leaves both the property and the field it would fill unmapped
    /// in that direction.
    /// </summary>
    [Fact]
    public async Task AMemberLeftOutOfTheWayToTheMessageIsReported()
    {
        var diagnostics = await DiagnosticsOf(Registry, """
            namespace Sample
            {
                public static class GrantMapper
                {
                    public static GrantMessage ToProto(this Grant grant) => new() { Subject = grant.Subject };

                    public static Grant FromProto(this GrantMessage message)
                        => new(message.Subject) { Scope = message.HasScope ? message.Scope : null };
                }
            }
            """);

        Assert.Equal(
            [("Sample.Grant.Scope", StoredTypeAnalyzer.ToMessage), ("Sample.GrantMessage.Scope", StoredTypeAnalyzer.ToMessage)],
            Reported(diagnostics, StoredTypeAnalyzer.MappingRule));
    }

    [Fact]
    public async Task AMemberLeftOutOfTheWayBackIsReported()
    {
        var diagnostics = await DiagnosticsOf(Registry, """
            namespace Sample
            {
                public static class GrantMapper
                {
                    public static GrantMessage ToProto(this Grant grant)
                        => new() { Subject = grant.Subject, Scope = grant.Scope ?? "" };

                    public static Grant FromProto(this GrantMessage message) => new(message.Subject);
                }
            }
            """);

        Assert.Equal(
            [("Sample.Grant.Scope", StoredTypeAnalyzer.FromMessage), ("Sample.GrantMessage.Scope", StoredTypeAnalyzer.FromMessage)],
            Reported(diagnostics, StoredTypeAnalyzer.MappingRule));
    }

    /// <summary>
    /// A property kept out of the message on purpose and marked so is not owed to either direction.
    /// </summary>
    [Fact]
    public async Task AnUnmappedPropertyMarkedNotStoredIsAccepted()
    {
        var diagnostics = await DiagnosticsOf(RegistryReading("SessionCodecs.All"), """
            namespace Sample
            {
                public sealed record Session(string Subject)
                {
                    [Abblix.Oidc.Server.Features.Storages.NotStored("lives in the cookie")]
                    public string? Persistence { get; init; }
                }

                public sealed class SessionMessage : Google.Protobuf.IMessage
                {
                    public const int SubjectFieldNumber = 1;
                    public string Subject { get; set; } = "";
                }

                public static class SessionCodecs
                {
                    public static readonly object[] All =
                    [
                        Abblix.Oidc.Server.Features.Storages.ProtobufCodecs.Mapped(
                            (Session session) => new SessionMessage { Subject = session.Subject },
                            message => new Session(message.Subject)),
                    ];
                }
            }
            """, CompleteMapper);

        Assert.Empty(diagnostics);
    }

    /// <summary>
    /// A property set once for every instance holds nothing a record could lose, while one a constructor sets does.
    /// </summary>
    [Fact]
    public async Task OnlyAGetOnlyPropertyAConstructorSetsIsOwed()
    {
        var diagnostics = await DiagnosticsOf(RegistryReading("VersionedCodecs.All"), """
            namespace Sample
            {
                public static class GrantMapper
                {
                    public static GrantMessage ToProto(this Grant grant)
                        => new() { Subject = grant.Subject, Scope = grant.Scope ?? "" };

                    public static Grant FromProto(this GrantMessage message)
                        => new(message.Subject) { Scope = message.HasScope ? message.Scope : null };
                }

                public sealed class Versioned
                {
                    public Versioned(string owner) => Owner = owner;
                    public int Version { get; } = 1;
                    public string Owner { get; }
                }

                public sealed class VersionedMessage : Google.Protobuf.IMessage
                {
                    public const int OwnerFieldNumber = 1;
                    public string Owner { get; set; } = "";
                }

                public static class VersionedCodecs
                {
                    public static readonly object[] All =
                    [
                        Abblix.Oidc.Server.Features.Storages.ProtobufCodecs.Mapped(
                            (Versioned value) => new VersionedMessage(),
                            message => new Versioned(message.Owner)),
                    ];
                }
            }
            """);

        Assert.Equal(
            [("Sample.Versioned.Owner", StoredTypeAnalyzer.ToMessage), ("Sample.VersionedMessage.Owner", StoredTypeAnalyzer.ToMessage)],
            Reported(diagnostics, StoredTypeAnalyzer.MappingRule));
    }

    /// <summary>
    /// A property a primary constructor sets through its initializer holds data, so a mapper leaving it out is
    /// reported.
    /// </summary>
    [Fact]
    public async Task APropertyAPrimaryConstructorSetsIsOwed()
    {
        var diagnostics = await DiagnosticsOf(CompleteMapper, RegistryReading("NoteCodecs.All"), """
            namespace Sample
            {
                public sealed class Note(string text, string extra)
                {
                    public string Text { get; } = text;
                    public string Extra { get; } = extra;
                }

                public sealed class NoteMessage : Google.Protobuf.IMessage
                {
                    public const int TextFieldNumber = 1;
                    public string Text { get; set; } = "";
                }

                public static class NoteCodecs
                {
                    public static readonly object[] All =
                    [
                        Abblix.Oidc.Server.Features.Storages.ProtobufCodecs.Mapped(
                            (Note note) => new NoteMessage { Text = note.Text },
                            message => new Note(message.Text, "")),
                    ];
                }
            }
            """);

        Assert.Equal(
            [("Sample.Note.Extra", StoredTypeAnalyzer.ToMessage)],
            Reported(diagnostics, StoredTypeAnalyzer.MappingRule));
    }

    /// <summary>
    /// A field of a message is shown on the codec writing that message, even when another codec reaching the same
    /// message comes first in source order.
    /// </summary>
    [Fact]
    public async Task AFieldIsShownOnTheCodecOfItsMessageRatherThanTheFirstReachingIt()
    {
        var diagnostics = await DiagnosticsOf(
            """
            namespace Sample
            {
                public sealed record Holder(Grant Grant);

                public sealed class HolderMessage : Google.Protobuf.IMessage
                {
                    public const int GrantFieldNumber = 1;
                    public GrantMessage Grant { get; set; } = new();
                }

                public static class HolderCodecs
                {
                    public static readonly object[] All =
                    [
                        Abblix.Oidc.Server.Features.Storages.ProtobufCodecs.Mapped(
                            (Holder holder) => new HolderMessage { Grant = holder.Grant.ToProto() },
                            message => new Holder(message.Grant.FromProto())),
                    ];
                }
            }
            """,
            RegistryReading("HolderCodecs.All"),
            """
            namespace Sample
            {
                public static class GrantMapper
                {
                    public static GrantMessage ToProto(this Grant grant) => new() { Subject = grant.Subject };

                    public static Grant FromProto(this GrantMessage message)
                        => new(message.Subject) { Scope = message.HasScope ? message.Scope : null };
                }
            }
            """);

        var field = Assert.Single(diagnostics, diagnostic =>
            diagnostic.Properties.GetValueOrDefault(StoredTypeAnalyzer.SubjectProperty) == "Sample.GrantMessage.Scope");
        Assert.Equal(
            "ProtobufCodecs.Mapped((Grant grant) => grant.ToProto(), message => message.FromProto())",
            (await field.Location.SourceTree!.GetTextAsync(TestContext.Current.CancellationToken))
                .ToString(field.Location.SourceSpan));
    }

    /// <summary>
    /// A finding about a property of a stored type is shown on the property, and one about a field of a message,
    /// which protoc writes, on the codec writing that message.
    /// </summary>
    [Fact]
    public async Task AFindingIsShownOnThePropertyOrOnTheCodecOfTheMessage()
    {
        var diagnostics = await DiagnosticsOf(Registry, """
            namespace Sample
            {
                public static class GrantMapper
                {
                    public static GrantMessage ToProto(this Grant grant) => new() { Subject = grant.Subject };

                    public static Grant FromProto(this GrantMessage message)
                        => new(message.Subject) { Scope = message.HasScope ? message.Scope : null };
                }
            }
            """);

        Assert.Equal(
            ["ProtobufCodecs.Mapped((Grant grant) => grant.ToProto(), message => message.FromProto())", "Scope"],
            diagnostics
                .Select(diagnostic => diagnostic.Location.SourceTree!
                    .GetText(TestContext.Current.CancellationToken)
                    .ToString(diagnostic.Location.SourceSpan))
                .Order(StringComparer.Ordinal));
    }

    /// <summary>
    /// A nested mapper handed to a helper as a method group is followed as surely as one called.
    /// </summary>
    [Fact]
    public async Task ANestedMapperHandedOnAsAMethodGroupIsChecked()
    {
        var diagnostics = await DiagnosticsOf(CompleteMapper, """
            namespace Sample
            {
                using System;

                public sealed record Holder(Grant Grant, string Owner);

                public sealed class HolderMessage : Google.Protobuf.IMessage
                {
                    public const int GrantFieldNumber = 1;
                    public GrantMessage Grant { get; set; } = new();

                    public const int OwnerFieldNumber = 2;
                    public string Owner { get; set; } = "";
                }

                public static class HolderMapper
                {
                    public static HolderMessage ToProto(Holder holder)
                        => new() { Grant = Apply(holder.Grant, GrantOf), Owner = holder.Owner };

                    public static Holder FromProto(HolderMessage message) => new(message.Grant.FromProto(), message.Owner);

                    private static TOut Apply<TIn, TOut>(TIn value, Func<TIn, TOut> map) => map(value);

                    private static GrantMessage GrantOf(Grant grant) => new() { Subject = grant.Subject };
                }

                public static class HolderCodecs
                {
                    [Abblix.Oidc.Server.Features.Storages.CodecRegistry]
                    public static readonly object[] All =
                    [
                        Abblix.Oidc.Server.Features.Storages.ProtobufCodecs.Mapped(
                            (Holder holder) => HolderMapper.ToProto(holder),
                            HolderMapper.FromProto),
                    ];
                }
            }
            """);

        Assert.Equal(
            [("Sample.Grant.Scope", StoredTypeAnalyzer.ToMessage), ("Sample.GrantMessage.Scope", StoredTypeAnalyzer.ToMessage)],
            Reported(diagnostics, StoredTypeAnalyzer.MappingRule));
    }

    /// <summary>
    /// A nested message built by a helper the mapper calls is held to the same rule as the outer one.
    /// </summary>
    [Fact]
    public async Task ANestedMessageMappedByAHelperIsChecked()
    {
        var diagnostics = await DiagnosticsOf(CompleteMapper, """
            namespace Sample
            {
                public sealed record Holder(Grant Grant, string Owner);

                public sealed class HolderMessage : Google.Protobuf.IMessage
                {
                    public const int GrantFieldNumber = 1;
                    public GrantMessage Grant { get; set; } = new();

                    public const int OwnerFieldNumber = 2;
                    public string Owner { get; set; } = "";
                }

                public static class HolderMapper
                {
                    public static HolderMessage ToProto(Holder holder)
                        => new() { Grant = GrantOf(holder.Grant), Owner = holder.Owner };

                    public static Holder FromProto(HolderMessage message) => new(message.Grant.FromProto(), message.Owner);

                    private static GrantMessage GrantOf(Grant grant) => new() { Subject = grant.Subject };
                }

                public static class HolderCodecs
                {
                    [Abblix.Oidc.Server.Features.Storages.CodecRegistry]
                    public static readonly object[] All =
                    [
                        Abblix.Oidc.Server.Features.Storages.ProtobufCodecs.Mapped(
                            (Holder holder) => HolderMapper.ToProto(holder),
                            HolderMapper.FromProto),
                    ];
                }
            }
            """);

        Assert.Equal(
            [("Sample.Grant.Scope", StoredTypeAnalyzer.ToMessage), ("Sample.GrantMessage.Scope", StoredTypeAnalyzer.ToMessage)],
            Reported(diagnostics, StoredTypeAnalyzer.MappingRule));
    }

    /// <summary>
    /// A project that only references the assembly declaring the codec sees none of its codecs, so it is not
    /// checked, rather than having every storage call of its tests reported.
    /// </summary>
    [Fact]
    public async Task ACompilationReferencingTheCodecIsNotChecked()
    {
        var diagnostics = await AnalyzerRun.DiagnosticsAcross(
            new StoredTypeAnalyzer(),
            ("Server", Infrastructure),
            ("Tests", Storing("public Task Save(int value) => storage.SetAsync(\"key\", value);")));

        Assert.Empty(diagnostics);
    }
}
