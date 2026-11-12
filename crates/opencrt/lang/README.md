# Translations

OpenCRT's interface text comes from two places: `crates/opencrt/ui/main.slint`,
where each visible string is marked with `@tr("...")`, and the Rust code, where
each text the user sees is marked with `tr!("...")`. This folder holds the
translations of both.

- `opencrt.pot` is the template: every text to translate.
- `<locale>/LC_MESSAGES/opencrt.po` is one language, for example
  `zh_CN/LC_MESSAGES/opencrt.po` for Simplified Chinese.

The translations here started as machine translations. Corrections from
native speakers are welcome as issues or pull requests that change the
`msgstr` lines.

The build compiles every `.po` file in this folder into OpenCRT. A new
language then shows in Global Options > General > Language. With "Follow the
system", OpenCRT uses the language that matches the system locale, else
English. A text without a translation shows in English.

## Add a language

1. Copy `opencrt.pot` to `<locale>/LC_MESSAGES/opencrt.po`.
2. In the header, set `Language: <locale>` and `charset=UTF-8`.
3. Fill in each `msgstr`. Keep `{}` and `{n}` placeholders, `\r` and `%h`
   style codes, and product names such as SSH2, SFTP or OpenCRT as they are.
4. Build OpenCRT and choose the language in Global Options.

## Update the template

If you add or change `@tr` or `tr!` text, write the template again from the
repository root. The script needs `slint-tr-extractor`
(`cargo install slint-tr-extractor`) and `python3`:

```
crates/opencrt/lang/update-template.sh
```

A unit test fails when a `tr!` text is missing from the template.

To bring a language up to date with the new template, run GNU gettext's
`msgmerge --update <locale>/LC_MESSAGES/opencrt.po opencrt.pot`.

Error texts from protocol code and libraries stay in English.
