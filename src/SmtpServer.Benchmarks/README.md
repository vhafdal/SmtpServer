# SMTP Server Benchmarks

Run the focused benchmark suite with:

```bash
DOTNET_ROLL_FORWARD=Major dotnet run -c Release --project src/SmtpServer.Benchmarks/SmtpServer.Benchmarks.csproj -- --filter "*"
```

Focused runs:

```bash
DOTNET_ROLL_FORWARD=Major dotnet run -c Release --project src/SmtpServer.Benchmarks/SmtpServer.Benchmarks.csproj -- --filter "*SmtpParserBenchmarks*"
DOTNET_ROLL_FORWARD=Major dotnet run -c Release --project src/SmtpServer.Benchmarks/SmtpServer.Benchmarks.csproj -- --filter "*AuthEhloBenchmarks*"
DOTNET_ROLL_FORWARD=Major dotnet run -c Release --project src/SmtpServer.Benchmarks/SmtpServer.Benchmarks.csproj -- --filter "*DataStoreBenchmarks*"
DOTNET_ROLL_FORWARD=Major dotnet run -c Release --project src/SmtpServer.Benchmarks/SmtpServer.Benchmarks.csproj -- --filter "*BdatCommandBenchmarks*"
```

## Coverage

- `SmtpParserBenchmarks` covers command parsing, including EHLO, MAIL, RCPT, AUTH, HELP, VRFY, EXPN, BDAT, PROXY, and unrecognized commands.
- `AuthEhloBenchmarks` covers EHLO response generation, successful AUTH PLAIN, and invalid AUTH PLAIN parsing.
- `ThroughputBenchmarks` covers end-to-end DATA delivery through MailKit for representative `.eml` files.
- `DataStoreBenchmarks` compares buffered DATA materialization with streaming DATA draining.
- `BdatCommandBenchmarks` compares buffered BDAT materialization with streaming BDAT draining for 1 KiB and 64 KiB bodies.

## Initial Optimization Candidates

1. Buffered BDAT currently materializes a full message body before calling `IMessageStore`; use benchmark results before changing this fallback path.
2. Parser multi-segment handling still has known gaps in `TokenReader.TryMake<TOut1,TOut2>`; benchmark any segment-aware parser changes against single-segment command lines.
3. Command-line size enforcement currently shares message-size plumbing; measure command parsing and body reads separately before splitting the limit path.
