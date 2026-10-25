# TMkUp v2.0 Specification

**Version:** 2.0  
**Status:** Final  
**File extension:** `.tmkup`

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Document Structure](#2-document-structure)
3. [Basic Formatting](#3-basic-formatting)
4. [ANSI Colors](#4-ansi-colors)
5. [Lists](#5-lists)
6. [Links](#6-links)
7. [Images (ASCII Conversion)](#7-images-ascii-conversion)
8. [Code Blocks](#8-code-blocks)
9. [Special Blocks](#9-special-blocks)
10. [Tables](#10-tables)
11. [Forms](#11-forms)
12. [Footnotes](#12-footnotes)
13. [Comments](#13-comments)
14. [Variables](#14-variables)
15. [Full Document Example](#15-full-document-example)

---

## 1. Introduction

TMkUp (Text Markup) is a markup language for the **TNet** text network. It is designed for creating documents that:

- Are human-readable in raw form.
- Support ANSI colors and basic formatting.
- Contain interactive elements (forms, spoilers) for clients that support them.

**Key principles:**
- Simplicity and readability.
- Unified syntax for all elements.
- Minimalism — no conditional blocks, only static markup.
- Extensibility through versioning.

---

## 2. Document Structure

A document may begin with an optional metadata block:

```tmkup
---tmk-meta
title: "Document Title"
author: "Author Name"
version: "2.0"
created: "2024-06-10"
variables:
  site_name: "TNet Hub"
---tmk-meta
```

Metadata may contain arbitrary keys. Clients may use them to display document information.

---

## 3. Basic Formatting

### Headings
```tmkup
# Heading 1 #
## Heading 2 ##
### Heading 3 ###
#### Heading 4 ####
##### Heading 5 #####
###### Heading 6 ######
```

### Text Styles
```tmkup
*italic*
**bold**
***bold italic***
~~strikethrough~~       (optional)
==highlight==            (optional)
`inline code`
^superscript^
~subscript~
```

### Horizontal Rules
```tmkup
---
***
```

---

## 4. ANSI Colors

Colors are set with tags `{color}...{/color}`. Text styles (`bold`, `italic`, etc.) do not have separate tags — use `*` and `**` instead.

```tmkup
{red}Red text{/red}
{green}Green text{/green}
{blue}Blue text{/blue}
{yellow}Yellow text{/yellow}
{magenta}Magenta text{/magenta}
{cyan}Cyan text{/cyan}
{white}White text{/white}
{black}Black text{/black}

{bg-red}Red background{/bg-red}
{bg-green}Green background{/bg-green}
{bg-blue}Blue background{/bg-blue}
{bg-yellow}Yellow background{/bg-yellow}
{bg-magenta}Magenta background{/bg-magenta}
{bg-cyan}Cyan background{/bg-cyan}
{bg-white}White background{/bg-white}
{bg-black}Black background{/bg-black}
```

**Bright colors:**
```tmkup
{bred}Bright red{/bred}
{bgreen}Bright green{/bgreen}
{byellow}Bright yellow{/byellow}
{bblue}Bright blue{/bblue}
{bmagenta}Bright magenta{/bmagenta}
{bcyan}Bright cyan{/bcyan}
{bwhite}Bright white{/bwhite}
{bblack}Bright black{/bblack}
```

**Bright backgrounds:**
```tmkup
{bg-bred}Bright red background{/bg-bred}
{bg-bgreen}Bright green background{/bg-bgreen}
{bg-byellow}Bright yellow background{/bg-byellow}
{bg-bblue}Bright blue background{/bg-bblue}
{bg-bmagenta}Bright magenta background{/bg-bmagenta}
{bg-bcyan}Bright cyan background{/bg-bcyan}
{bg-bwhite}Bright white background{/bg-bwhite}
{bg-bblack}Bright black background{/bg-bblack}
```

**Combining color and style:**
```tmkup
{red}*Red italic*{/red}
{green}**Green bold**{/green}
{blue}***Blue bold italic***{/blue}
{red}Red {green}green inside{/green} red again{/red}
```

**Reset all styles:**
```tmkup
{red}Red text **{/}** and now normal
```

---

## 5. Lists

### Unordered List
```tmkup
- Item 1
- Item 2
  - Nested item
    - Deep level
```

### Ordered List
```tmkup
1. First item
2. Second item
   1. Nested item
   2. Another one
```

### Task List
```tmkup
- [ ] Uncompleted task
- [x] Completed task  
- [~] Task in progress
```

### Definition List
```tmkup
Term 1
: Definition of the first term
: Second definition

Term 2
: Definition of the second term
```

---

## 6. Links

```tmkup
[Link text](/path/to/doc.tmkup)
```

No tooltip support.

---

## 7. Images (ASCII Conversion)

```tmkup
![Logo](logo.png)
![Diagram](diagram.png {height=90})
```

- The `height` parameter specifies the desired height in characters (optional).
- Width is calculated automatically based on aspect ratio and the half-block rendering system.
- The client should convert the image to ASCII art.
- If conversion is not possible, the alt text is shown in square brackets.

---

## 8. Code Blocks

**Inline code:**
```tmkup
`console.log("Hello")`
```

**Code blocks:**
````
```python
def hello():
    print("Hello World!")
```
````

---

## 9. Special Blocks

### 9.1. Info Blocks

Blocks start with `!!!` and contain a `type` attribute (`info`, `warning`, `success`, `error`).

```tmkup
!!! {type="info"}
Informational message
With *formatting* support
!!!

!!! {type="warning"}
Important warning
!!!

!!! {type="success"}
Successful execution
!!!

!!! {type="error"}
Execution error
!!!
```

**Display in terminal:**
- `info` → blue, prefix `[INFO]`
- `warning` → yellow, prefix `[WARN]`
- `success` → green, prefix `[ OK ]`
- `error` → red, prefix `[ERR ]`

### 9.2. Color Blocks with Border

Blocks are enclosed between `%%` and may have `color` and `border` attributes.

```tmkup
%% {color="blue" border="left"}
Block with left border
%%

%% {color="green" border="rounded"}
Block with rounded border
%%
```

**Display:** the border is drawn with box-drawing characters (`┌─┐`, `└─┘`, `├─┤`, etc.) in the specified color.

### 9.3. Spoilers (Hidden Content)

A spoiler starts with `???` and may have a `title` attribute. Content is hidden until the user presses a key.

```tmkup
??? 
Hidden content
Shown on Enter press
???

??? {title="Show answer"}
Secret answer: **42**
???
```

In text mode, the spoiler is displayed as `[▶] Title` (if title is set) or `[▶] Spoiler`. Pressing Enter expands the content.

### 9.4. Quotes

```tmkup
> Standard quote
> Multiline quote
> — Author of the quote

> {cite="John Doe" date="2024"}
> Quote with author and date
```

---

## 10. Tables

Tables use standard Markdown syntax.

```tmkup
| Name | Age | City |
|------|-----|------|
| John | 25  | Moscow |
| Anna | 30  | Saint Petersburg |
| Peter| 35  | Kazan |
```

Alignment:
```tmkup
| Left | Center | Right |
|:-----|:------:|------:|
| text | text   | text  |
```

---

## 11. Forms

Forms are used to send data to the server. They are enclosed between `@@` and contain fields.

```
@@ {action="/path" method="post"}
... fields ...
@@
```

**Required form attributes:** `action`, `method` (only `post`).

### 11.1. Text Fields
```tmkup
[Your name] {type="text" name="username" placeholder="Name" required}
[Email] {type="email" name="email" placeholder="user@example.com" required}
[Password] {type="password" name="password" required}
[Message] {type="textarea" name="message" rows="4" placeholder="Text"}
```

### 11.2. Checkboxes
```tmkup
[I agree to the terms] {type="checkbox" name="agree" checked}
[Subscribe to newsletter] {type="checkbox" name="newsletter"}
```

### 11.3. Radio Buttons (Block Syntax)
```
[radio name="gender"]
  [Male] {value="male" checked}
  [Female] {value="female"}
[/radio]
```

### 11.4. Select Dropdown (Block Syntax)
```
[select name="city"]
  [Moscow] {value="msk" selected}
  [Saint Petersburg] {value="spb"}
  [Kazan] {value="kzn"}
[/select]
```

Multiple selection:
```
[select name="tags" multiple]
  [News] {value="news" selected}
  [Blog] {value="blog"}
  [Articles] {value="articles" selected}
[/select]
```

### 11.5. Buttons
```tmkup
[Submit] {type="submit"}
[Reset] {type="reset"}
```

### 11.6. Hidden Field
```tmkup
[ ] {type="hidden" name="token" value="abc123"}
```

### 11.7. Full Form Example
```tmkup
@@ {action="/register" method="post"}

[Your name] {type="text" name="username" placeholder="Name" required}
[Email] {type="email" name="email" placeholder="user@example.com" required}
[Password] {type="password" name="password" required}

Country:
[select name="country"]
  [Russia] {value="ru" selected}
  [USA] {value="us"}
  [Germany] {value="de"}
[/select]

[I agree to the terms] {type="checkbox" name="agree" required}
[Subscribe to newsletter] {type="checkbox" name="newsletter" checked}

Gender:
[radio name="gender"]
  [Male] {value="male" checked}
  [Female] {value="female"}
[/radio]

[Comment] {type="textarea" name="message" rows="4"}

[Submit] {type="submit"}
[Reset] {type="reset"}

@@
```

---

## 12. Footnotes

```tmkup
Text with a footnote[^1] and another one[^2].

[^1]: First footnote
[^2]: Second footnote with *formatting*
```

---

## 13. Comments

```tmkup
// Single-line comment

/*
   Multi-line
   comment
*/
```

---

## 14. Variables

Variables are defined in the metadata block and used via `{{ variable }}`.

```tmkup
---tmk-meta
variables:
  site_name: "TNet Hub"
  date: "2024-06-10"
---tmk-meta

Welcome to {{ site_name }}.
Today: {{ date }}.
```

---

## 15. Full Document Example

```tmkup
---tmk-meta
title: "Welcome to TNet"
author: "admin"
created: "2024-06-10"
variables:
  site_name: "TNet Hub"
---tmk-meta

# Home Page

*Welcome* to **TNet** — the new text network.

{green}This text is green.{/green}
{red}**And this is red and bold!**{/red}

## ASCII Image

![TNet Logo](logo.png {height=60})

## Navigation

- [Home](/index.tmkup)
- [About](/about.tmkup)
- [Documentation](/docs/)

## Spoiler

??? {title="Show answer"}
Secret answer: **42**
???

## Feedback Form

@@ {action="/feedback" method="post"}

[Name] {type="text" name="name" placeholder="Your name" required}
[Email] {type="email" name="email" placeholder="user@example.com" required}
[Message] {type="textarea" name="message" rows="4"}

[ ] {type="checkbox" name="agree" checked} I agree to data processing

[Submit] {type="submit"}
[Reset] {type="reset"}

@@

---

// Comment
© 2024 TNet Community
```

---

**End of TMkUp v2.0 Specification**
