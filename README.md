<!-- markdownlint-disable MD041 MD033 -->

[![Python](https://img.shields.io/badge/python-%2302569B.svg?style=for-the-badge&logo=python&logoColor=white)](https://python.org)

[![GitHub License](https://img.shields.io/github/license/anusii/solidtools)](https://raw.githubusercontent.com/anusii/solidtools/dev/LICENSE)
[![GitHub Version](https://img.shields.io/badge/dynamic/yaml?url=https://raw.githubusercontent.com/anusii/solidtools/master/pubspec.yaml&query=$.version&label=version&logo=github)](https://github.com/anusii/solidtools/blob/dev/CHANGELOG.md)
[![Pub Version](https://img.shields.io/pub/v/solidtools?label=pub.dev&labelColor=333940&logo=flutter)](https://pub.dev/packages/solidtools)
[![GitHub Last Updated](https://img.shields.io/github/last-commit/anusii/solidtools?label=last%20updated)](https://github.com/anusii/solidtools/commits/dev/)
[![GitHub Commit Activity (main)](https://img.shields.io/github/commit-activity/w/anusii/solidtools/main)](https://github.com/anusii/solidtools/commits/dev/)
[![GitHub Issues](https://img.shields.io/github/issues/anusii/solidtools)](https://github.com/anusii/solidtools/issues)

# Solid Tools

A collection of scripts for managing PODs and solid servers

## Read Encrypted

Read an encrypted file in a POD and decrypt its content.

This can be used on a server that hosts a community solid server.

Usage:

```console
$ python3 read_encrypted.py <relative_or_absolute_file_path>
Security Key:
```

and then provide you security key after the prompt.

Example:

```bash
python3 read_encrypted.py server/honky_tonk/notepod/data/note-20250527T141838.ttl
```

The original document is:

```console
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix solidTerms: <https://solidcommunity.au/predicates/terms#> .

<https://pods.solidcommunity.au/watson02/notepod/data/note-20251001T085544.ttl>
    solidTerms:path "notepod/data/note-20251001T085544.ttl"^^xsd:string ;
    solidTerms:iv "1WJKXE/UcnEPvJOIO2kPPg=="^^xsd:string ;
    solidTerms:encData "aLjJXRKVzJ/on00X5hld7/...syKg=="^^xsd:string .
```

The decrypted data (the contents of the `encData` field), after
supplying the secret key:

```console
Security Key:
@prefix : <#>.
      @prefix foaf: <http://xmlns.com/foaf/0.1/>.
      @prefix terms: <http://purl.org/dc/terms/>.
      @prefix notepodTerms: <https://solidcommunity.au/predicates/terms#>.
      :me
          a foaf:PersonalProfileDocument;
          terms:title "Note";
          notepodTerms:createdDateTime "20251001T085544";
          notepodTerms:modifiedDateTime "20251001T085544";
          notepodTerms:noteTitle "My First Note";
          notepodTerms:noteContent "3JBoN1TjjkndQowxrZt1lA==".
```
