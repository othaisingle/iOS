# Binary

## lib_mod_info.py

It is used to modify an iOS application’s `.ipa` file, allowing analysts or developers to set a target iOS version and optionally define a custom output filename for repackaging or sideloading purposes.

**Basic Usage**

```bash
python3 lib_mod_info.py app.ipa
```

**Specify a Target iOS Version**

```bash
python3 lib_mod_info.py app.ipa --version 15.0
```

Specify a Custom Output File Name

```bash
python3 lib_mod_info.py app.ipa --output my_modified_app.ipa
```

**Combined Usage Examples**

```
python3 lib_mod_info.py app.ipa --version 14.0 --output downgraded_app.ipa
```



## lib_get_info.py

It is also a lightweight IPA Inspector utility that extracts and summarizes key metadata from an `.ipa` file. By default, it outputs a concise summary of essential information; when the `--search` option is specified, it presents the results in a well-formatted, searchable table for easier review and analysis.

**Show summary info (default mode)**

```
python3 lib_get_info.py MyApp.ipa
```

 **Search for a specific keyword**

```
python3 lib_get_info.py MyApp.ipa --search bundle
```

or shorter:

```
python3 lib_get_info.py MyApp.ipa -s bundle
```

Search with custom wrap width

```
python3 lib_get_info.py MyApp.ipa -s version --wrap 120
```

