// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace Abblix.Analyzers;

/// <summary>
/// Refuses a logging call that writes a value from outside other than sanitized, and a credential other than as its
/// fingerprint.
/// </summary>
/// <remarks>
/// <para>
/// A call is a logging call when its method carries <c>[LoggerMessage]</c>, the only way this code writes a record.
/// Each argument is followed back through the locals of its method, so a value copied, converted, interpolated or
/// joined on its way is still found; what <see cref="ValueSources"/> follows and where it stops is written there. A
/// value is from outside when it is read from a type marked <c>[ExternalInput]</c> or one deriving from it, or is such
/// a type itself; it is a credential when it is read from a member or a parameter marked <c>[Credential]</c>. Both
/// marks are asked of the symbol, so a renamed property keeps its mark and a property of the same name elsewhere does
/// not gain it.
/// </para>
/// <para>
/// A method's own parameter is not followed into its callers, so a credential handed to a method arrives unmarked
/// unless that parameter carries <c>[Credential]</c> itself. A parameter of the logging call whose type is a value
/// type other than the two wrappers - a count, a flag, an instant - is left alone, since it cannot carry the text a
/// sender chose.
/// </para>
/// </remarks>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class LoggedValueAnalyzer : DiagnosticAnalyzer
{
    /// <summary>The attribute that makes a method a logging call.</summary>
    internal const string LoggerMessageAttributeName = "Microsoft.Extensions.Logging.LoggerMessageAttribute";

    /// <summary>The wrapper a value from outside is logged through.</summary>
    internal const string SanitizedName = "Abblix.Utils.Sanitized";

    /// <summary>The wrapper a credential is logged through.</summary>
    internal const string FingerprintName = "Abblix.Utils.Fingerprint";

    /// <summary>The mark of a type whose values arrive from outside.</summary>
    internal const string ExternalInputAttributeName = "Abblix.Utils.ExternalInputAttribute";

    /// <summary>The mark of a member or a parameter holding a credential.</summary>
    internal const string CredentialAttributeName = "Abblix.Utils.CredentialAttribute";

    /// <summary>The diagnostic reported for a value from outside logged unsanitized.</summary>
    public static readonly DiagnosticDescriptor ExternalInputRule = new(
        id: "ABX1007",
        title: "A value from outside reaches the log unsanitized",
        messageFormat: "'{0}' is logged as {1} and carries a value from outside: declare it as Sanitized",
        category: "Abblix.Conventions",
        defaultSeverity: DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    /// <summary>The diagnostic reported for a credential logged other than as its fingerprint.</summary>
    public static readonly DiagnosticDescriptor CredentialRule = new(
        id: "ABX1008",
        title: "A credential reaches the log other than as its fingerprint",
        messageFormat: "'{0}' is logged as {1} and carries a credential: declare it as Fingerprint",
        category: "Abblix.Conventions",
        defaultSeverity: DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    /// <inheritdoc />
    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics
        => ImmutableArray.Create(ExternalInputRule, CredentialRule);

    /// <inheritdoc />
    public override void Initialize(AnalysisContext context)
    {
        // The logging source generator writes the bodies, never the calls, so generated code holds nothing to judge.
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterCompilationStartAction(start =>
        {
            // A compilation that cannot see the attributes and the wrappers has nothing marked and nothing to log
            // through, so there is no rule to hold it to.
            if (LoggedValueTypes.Of(start.Compilation) is { } types)
            {
                var sources = new ValueSources(start.Compilation);
                start.RegisterOperationAction(
                    operation => Analyze(operation, types, sources),
                    OperationKind.Invocation);
            }
        });
    }

    private static void Analyze(OperationAnalysisContext context, LoggedValueTypes types, ValueSources sources)
    {
        var invocation = (IInvocationOperation)context.Operation;
        if (!types.IsLoggingCall(invocation.TargetMethod))
            return;

        foreach (var argument in invocation.Arguments)
        {
            if (argument.Parameter is not { } parameter || !types.CanCarryText(parameter.Type))
                continue;

            var reads = sources.Of(argument.Value).ToArray();
            if (!types.IsFingerprint(parameter.Type) && reads.Any(types.ReadsCredential))
                Report(context, CredentialRule, argument, parameter);
            else if (!types.IsWrapped(parameter.Type) && reads.Any(types.ReadsExternalInput))
                Report(context, ExternalInputRule, argument, parameter);
        }
    }

    private static void Report(
        OperationAnalysisContext context,
        DiagnosticDescriptor rule,
        IArgumentOperation argument,
        IParameterSymbol parameter)
    {
        var type = parameter.Type.ToDisplayString(SymbolDisplayFormat.MinimallyQualifiedFormat);
        context.ReportDiagnostic(Diagnostic.Create(rule, argument.Syntax.GetLocation(), parameter.Name, type));
    }
}
