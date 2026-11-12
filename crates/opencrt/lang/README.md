# Translations

OpenCRT's interface text comes from `crates/opencrt/ui/main.slint`, where each
visible string is marked with `@tr("...")`. This folder holds the translations.

- `opencrt.pot` is the template: every text to translate.
- `<locale>/LC_MESSAGES/opencrt.po` is one language, for example
  `zh_CN/LC_MESSAGES/opencrt.po` for Simplified Chinese.

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

If you add or change `@tr` text in `main.slint`, extract the template again
from the repository root. `slint-tr-extractor` comes from
`cargo install slint-tr-extractor`:

```
slint-tr-extractor --no-default-translation-context --package-name OpenCRT -o crates/opencrt/lang/opencrt.pot crates/opencrt/ui/*.slint
```

To bring a language up to date with the new template, run GNU gettext's
`msgmerge --update <locale>/LC_MESSAGES/opencrt.po opencrt.pot`.

Texts that the Rust code shows (status bar messages, errors) are not
translated yet.
