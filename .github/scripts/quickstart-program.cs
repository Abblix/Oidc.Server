#:package Microsoft.CodeAnalysis.CSharp@5.12.0

// Writes the Program.cs a reader of a README quickstart ends up with: the README block as pasted, taken from its
// compiled copy under tests/Abblix.DocSamples/Samples (ReadmeSampleTests holds each copy to its README's lines),
// with nothing added. The release workflow builds the result in a project made by `dotnet new web`.
//
//   dotnet quickstart-program.cs <path to the compiled copy> <path of the Program.cs to write>
//
// The block is read as C# syntax, never as text: the statements between the copy's `// <sample>` and
// `// </sample>` markers become the top-level statements, and a statement of the method outside them is refused,
// since it would be code the reader never sees. The file pins its own Roslyn version, which the central package
// versions of this repository refuse, so the workflow copies it to an empty folder and runs it there.

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

if (args is not [var samplePath, var programPath])
{
    Console.Error.WriteLine("Usage: dotnet quickstart-program.cs <compiled copy of the block> <Program.cs to write>");
    return 2;
}

var tree = CSharpSyntaxTree.ParseText(File.ReadAllText(samplePath), path: samplePath);
var errors = tree.GetDiagnostics().Where(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error).ToList();
if (errors.Count > 0)
{
    foreach (var error in errors)
        Console.Error.WriteLine(error);
    return 1;
}

var unit = tree.GetCompilationUnitRoot();
var configure = unit.DescendantNodes()
    .OfType<MethodDeclarationSyntax>()
    .Where(method => method is { Identifier.Text: "Configure", Body: not null })
    .ToList();
if (configure is not [{ Body: { } body }])
    return Fail($"{samplePath} declares {configure.Count} Configure methods with a body, where the copy of a quickstart has one");

var opening = Marker(body, "// <sample>");
var closing = Marker(body, "// </sample>");
if (opening is not [var start] || closing is not [var end] || end.SpanStart < start.Span.End)
{
    return Fail($"{samplePath} marks its sample with {opening.Count} '// <sample>' and {closing.Count} '// </sample>' "
                + "comments, where the copy of a quickstart has one of each, in that order");
}

var outside = body.Statements
    .Where(statement => statement.SpanStart < start.Span.End || statement.Span.End > end.SpanStart)
    .ToList();
if (outside.Count > 0)
{
    return Fail($"{samplePath} has {outside.Count} statements outside its sample markers, starting with "
                + $"'{outside[0]}', which a reader of the README would not have");
}

if (body.Statements.Count == 0)
    return Fail($"{samplePath} has no statement between its sample markers");

// Each node keeps its own comments and line breaks, so the file reads like the README block it came from
var program = string.Concat(unit.Usings.Select(directive => directive.WithoutLeadingTrivia().ToFullString()))
              + string.Concat(body.Statements.Select(statement => statement.ToFullString()));

File.WriteAllText(programPath, program);
Console.WriteLine($"Wrote {programPath}:");
Console.WriteLine(program);
return 0;

static List<SyntaxTrivia> Marker(BlockSyntax body, string text)
    => body.DescendantTrivia()
        .Where(trivia => trivia.IsKind(SyntaxKind.SingleLineCommentTrivia) && trivia.ToString().Trim() == text)
        .ToList();

static int Fail(string message)
{
    Console.Error.WriteLine(message);
    return 1;
}
