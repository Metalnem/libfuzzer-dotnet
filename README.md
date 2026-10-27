# libfuzzer-dotnet

[![Build Status][build-shield]][build-link]
[![License][license-shield]][license-link]

[build-shield]: https://github.com/metalnem/libfuzzer-dotnet/actions/workflows/release.yml/badge.svg
[build-link]: https://github.com/metalnem/libfuzzer-dotnet/actions/workflows/release.yml
[license-shield]: https://img.shields.io/badge/license-MIT-blue.svg?style=flat
[license-link]: https://github.com/metalnem/libfuzzer-dotnet/blob/master/LICENSE

libFuzzer driver for SharpFuzz. Read [Using libFuzzer with SharpFuzz] for usage instructions.

[Using libFuzzer with SharpFuzz]: https://github.com/Metalnem/sharpfuzz/blob/master/docs/libFuzzer.md

## .NET tool

The native tool packages require the .NET 10 SDK or later for installation.

```shell
dotnet tool install --global libfuzzer-dotnet
```

Run the driver directly:

```shell
dotnet-libfuzzer --target_path=dotnet --target_arg=path/to/FuzzTarget.dll corpus
```

Or through the .NET CLI:

```shell
dotnet libfuzzer --target_path=dotnet --target_arg=path/to/FuzzTarget.dll corpus
```
