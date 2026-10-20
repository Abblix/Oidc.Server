// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Abblix.Analyzers;

/// <summary>
/// Refuses a type handed to the OIDC server's entity storage with no Protocol Buffers codec, and a codec whose mapper
/// leaves a field or a property out of either direction.
/// </summary>
/// <remarks>
/// <para>
/// The server's serializer writes a type with no codec as JSON and says so only in a warning. JSON carries no field
/// numbers, so two versions of the server running side by side during a deploy can misread each other's records. A
/// call to the storage is found by the method it calls, on the storage interface or a type implementing it, and its
/// type is the call's type argument; a call whose type argument is a type parameter passes the decision to its own
/// caller. A type has a codec when a <c>ProtobufCodec&lt;T&gt;</c> of it is built anywhere in the compilation, or, for
/// a write, when a base type has one, as the serializer looks a written value's codec up by its base types too. A type
/// meant to stay JSON carries <c>[StoredAsJson]</c> with the reason.
/// </para>
/// <para>
/// A mapped codec is checked in both directions, because a property one mapper forgets is dropped on every write with
/// nothing to report it. What <see cref="StoredMapping"/> counts as taking part, and where it stops looking, is
/// written there. A property kept out of the message on purpose carries <c>[NotStored]</c> with the reason. The check
/// shows that every member takes part, not that it lands in the right place: a round-trip test shows that.
/// </para>
/// <para>
/// Both rules are decided once the whole compilation is seen, so they are reported by the build rather than as the
/// code is typed, and only in the assembly that declares the codec, the one place its codecs are visible. A storage
/// call in another assembly is not checked.
/// </para>
/// </remarks>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class StoredTypeAnalyzer : DiagnosticAnalyzer
{
    /// <summary>The storage whose calls are checked.</summary>
    internal const string StorageName = "Abblix.Oidc.Server.Features.Storages.IEntityStorage";

    /// <summary>The codec a stored type is served by.</summary>
    internal const string CodecName = "Abblix.Oidc.Server.Features.Storages.ProtobufCodec`1";

    /// <summary>The mark of a type stored as JSON on purpose.</summary>
    internal const string StoredAsJsonName = "Abblix.Oidc.Server.Features.Storages.StoredAsJsonAttribute";

    /// <summary>The mark of a property kept out of the stored message on purpose.</summary>
    internal const string NotStoredName = "Abblix.Oidc.Server.Features.Storages.NotStoredAttribute";

    /// <summary>The interface every Protocol Buffers message implements.</summary>
    internal const string MessageName = "Google.Protobuf.IMessage";

    /// <summary>The diagnostic property naming the type or the member reported.</summary>
    public const string SubjectProperty = "Subject";

    /// <summary>The diagnostic property naming the direction a member is missing from.</summary>
    public const string DirectionProperty = "Direction";

    /// <summary>The direction that writes a stored value out as its message.</summary>
    public const string ToMessage = "ToMessage";

    /// <summary>The direction that reads a stored value back from its message.</summary>
    public const string FromMessage = "FromMessage";

    /// <summary>The diagnostic reported for a stored type with no codec.</summary>
    public static readonly DiagnosticDescriptor CodecRule = new(
        id: "ABX1009",
        title: "A stored type has no protobuf codec",
        messageFormat: "'{0}' is passed to {1} with no protobuf codec: add one to the codec registry, " +
                       "or mark the type [StoredAsJson] with the reason",
        category: "Abblix.Conventions",
        defaultSeverity: DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        customTags: WellKnownDiagnosticTags.CompilationEnd);

    /// <summary>The diagnostic reported for a member the mapper of a codec leaves out of one direction.</summary>
    public static readonly DiagnosticDescriptor MappingRule = new(
        id: "ABX1010",
        title: "A stored member is mapped in one direction only, or in none",
        messageFormat: "'{0}' is not mapped {1}: map it both ways, or mark the property [NotStored] with the reason",
        category: "Abblix.Conventions",
        defaultSeverity: DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        customTags: WellKnownDiagnosticTags.CompilationEnd);

    /// <inheritdoc />
    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics
        => ImmutableArray.Create(CodecRule, MappingRule);

    /// <inheritdoc />
    public override void Initialize(AnalysisContext context)
    {
        // The generated code is the messages themselves, read as symbols; no storage call or mapper is generated.
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterCompilationStartAction(start =>
        {
            // A compilation that cannot see the storage or the codec stores nothing this rule is about.
            if (StoredTypes.Of(start.Compilation) is not { } types)
                return;

            var mapping = new StoredMapping(types);
            start.RegisterOperationAction(mapping.CollectInvocation, OperationKind.Invocation);
            start.RegisterOperationBlockAction(mapping.CollectBody);
            start.RegisterCompilationEndAction(mapping.Report);
        });
    }
}
