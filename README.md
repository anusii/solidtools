# Solid Tools

A collection of scripts for managing PODs and solid servers

## Read Encrypted

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

The decrypted document, after supplying the secret key:

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
