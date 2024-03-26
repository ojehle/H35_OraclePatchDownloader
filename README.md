# Oracle Patch Downloader

The Oracle Patch Downloader can be used to download a list of
patches from My Oracle Support.

It is written in Java and based on
[HtmlUnit](https://www.htmlunit.org/), which has the big
advantage that it simulates a browser very closely, including
execution of JavaScript.  This should (hopefully) allow for more
stable web scraping, even if Oracle should decide to change
anything in the logon or download procedure.  However, using
HtmlUnit comes with the disadvantage that this tool requires the
inclusion of quite some dependencies, resulting in a relatively
big executable jar.

There are other similar tools available, for example
[oracle_quarter_patch_downloader](https://github.com/lucaslellis/oracle_quarter_patch_downloader)
or [getMOSPatch](https://github.com/MarisElsins/getMOSPatch), the
latter of which is reported to be
[broken](https://github.com/MarisElsins/getMOSPatch/issues/34).

The Oracle Quarter Patch Downloader provides additional logic to
download important database and GI patches based on the Automated
Release Update (ARU) catalog.  However, it is controlled by input
files, while this tool is completely command-line-driven and,
hence, slightly more scripting-friendly.

## Prerequisites

- My Oracle Support Account
- JRE version >= 1.8
- JDK version >= 1.8 and Maven version >= 3.5.4 (only if you plan
  to build the Oracle Patch Downloader yourself from its sources)

## Usage

Download the latest release of the Oracle Patch Downloader jar
from its [GitHub release page](https://github.com/ojehle/H35_OraclePatchDownloader/releases).
Then start it as

```
java -jar OraclePatchDownloader-1.0.4.jar
```

which should bring up the short usage description shown below.

You can use this tool to download a list of patches, the regex
can be used to filter out files.  You can specify the patch list
and the platform/language list either as comma-separated lists
(`-x p12345678,6880880`) or through multiple repeated options
(`-x p12345678 -x 6880880`) or through a combination of both.

```
 -h : --help        help text

 -D : --debug       debug mode

 -q : --quiet       quiet mode

 -d : --directory   output folder, default user home

 -x : --patches     list of patches
                    (e.g. "p12345678", "12345678")

 -f : --patchfile   file containing list of patches, one patch per line
                    (e.g. "p12345678", "12345678", "# comment")

 -t : --platforms   list of platforms or languages
                    (e.g. "226P" for Linux x86-64 or "4L" for German (D))

 -r : --regex       regex for file filter, multiple possible
                    (e.g. ".*1900.*")

 -u : --user        email/userid

 -p : --password    password ("env:ENV_VAR" to use password from env)

 -T : --temp        temporary directory
```

### Specifying Passwords

Specifying passwords on the command line is inherently unsafe, in
particular on multi-user systems.  You should better enter the
password interactively in the console, which is the default if
you do not specify option `--password`.

Or you can store the password in an environment variable and pass
a reference to that variable in the argument to option
`--password`, as shown in the example below.

### Debug Mode

In debug mode the Oracle Patch Downloader dumps all HTML pages
that it processes to the output folder.  In addition, it logs
HTTP requests and responses to a log file, also placed in the
output folder.  The downloader uses file names
`dump-<hex-timestamp>-<page-title>.xml` for dumps of regular
pages and file names `error-<hex-timestamp>-<page-title>.xml` for
dumps of pages it could not process.

**Note that the log file most certainly contains sensitive data,
likewise for the page dumps.**

The Downloader uses the APIs provided by HtmlUnit to dump HTML
pages and log HTTP requests and responses.  The information
retrieved through these APIs differs from the actual data sent
over the wire.

### Example

```sh
export MOS_PASSWORD="my secret MOS password"
java -jar OraclePatchDownloader-1.0.4.jar -u user@h35.li -p env:MOS_PASSWORD \
     -x 200000 -t 226P,4L -r ".*1900.*" -r ".*19190.*" -d $HOME/Downloads
```

## Installation

To build the Oracle Patch Downloader from its sources execute the
following commands:

```sh
git clone git@github.com:ojehle/H35_OraclePatchDownloader.git
cd H35_OraclePatchDownloader
mvn install
cd target
java -jar OraclePatchDownloader-1.0.4.jar
```

The resulting jar is self-contained and does not require any
additional dependencies during runtime.

## Plattform and Language Codes

| Code   | Plattform                                      |
|--------|------------------------------------------------|
| 537P   | Acme Packet 1100                               |
| 529P   | Acme Packet 3820                               |
| 540P   | Acme Packet 3900                               |
| 561P   | Acme Packet 3950                               |
| 530P   | Acme Packet 4500                               |
| 538P   | Acme Packet 4600                               |
| 560P   | Acme Packet 4900                               |
| 534P   | Acme Packet 6100                               |
| 531P   | Acme Packet 6300                               |
| 551P   | Acme Packet 6350                               |
| 527P   | Acme Packet OS                                 |
| 512P   | Apple iOS                                      |
| 293P   | Apple Mac OS X (Intel) (32-bit)                |
| 522P   | Apple Mac OS X (Intel) (64-bit)                |
| 421P   | Apple Mac OS X (PowerPC)                       |
| 553P   | Apple macOS                                    |
| 559P   | Apple macOS ARM (64-bit)                       |
| 516P   | Embedded Linux ARM                             |
| 521P   | Embedded Linux on cnMIPS                       |
| 519P   | Embedded Linux on POWER e500v2                 |
| 517P   | Embedded Linux on POWER Systems                |
| 294P   | Embedded Linux SH4                             |
| 515P   | Embedded Linux x86                             |
| 228P   | FreeBSD - x86                                  |
| 361P   | Fujitsu BS2000                                 |
| 312P   | Fujitsu BS2000/OSD (SQ series)                 |
| 285P   | Fujitsu BS2000/OSD (SX series)                 |
| 504P   | Fujitsu MSP-EX                                 |
| 513P   | Google Android                                 |
| 554P   | Google Android 9                               |
| 549P   | HP NonStop (Guardian) on x86                   |
| 548P   | HP NonStop (OSS) on x86                        |
| 304P   | HP NonStop Itanium (Guardian)                  |
| 308P   | HP NonStop Itanium (OSS)                       |
| 303P   | HP NonStop S-series (Guardian)                 |
| 89P    | HP OpenVMS Alpha                               |
| 243P   | HP OpenVMS Itanium                             |
| 1P     | HP OpenVMS VAX                                 |
| 87P    | HP Tru64 UNIX                                  |
| 197P   | HP-UX Itanium                                  |
| 278P   | HP-UX Itanium (32-bit)                         |
| 999P   | HP-UX PA-RISC (32-bit)                         |
| 59P    | HP-UX PA-RISC (64-bit)                         |
| 299P   | ia64                                           |
| 319P   | IBM AIX on POWER Systems (32-bit)              |
| 212P   | IBM AIX on POWER Systems (64-bit)              |
| 43P    | IBM i on POWER Systems                         |
| 211P   | IBM S/390 Based Linux (31-bit)                 |
| 30P    | IBM z/OS on System z                           |
| 314P   | IBM z/VM on System z                           |
| 227P   | IBM: Linux on POWER Big Endian Systems         |
| 542P   | IBM: Linux on POWER Little Endian Systems      |
| 209P   | IBM: Linux on System z                         |
| 297P   | iTron                                          |
| 528P   | Linux ARM 32-bit VFP HardFP ABI                |
| 523P   | Linux ARM 32-bit VFP SoftFP ABI                |
| 564P   | Linux ARM 64 bit (DB19 OL79)                   |
| 541P   | Linux ARM 64-bit                               |
| 214P   | Linux Itanium                                  |
| 556P   | Linux MIPS 64-bit                              |
| 525P   | Linux SPARC                                    |
| 46P    | Linux x86                                      |
| 226P   | Linux x86-64                                   |
| 99999P | Metadata-Only Patch                            |
| 912P   | Microsoft Windows (32-bit)                     |
| 558P   | Microsoft Windows AArch64                      |
| 208P   | Microsoft Windows Itanium (64-bit)             |
| 539P   | Microsoft Windows Phone                        |
| 233P   | Microsoft Windows x64 (64-bit)                 |
| 276P   | Monta Vista x86                                |
| 277P   | Monta Vista x86-64                             |
| 536P   | Net-Net 4250                                   |
| 533P   | Net-Net 9200                                   |
| 547P   | Netra Server X5-2 for Communications           |
| 535P   | Netra X3-2 for Acme Packet                     |
| 1234P  | NLS Generic Platform                           |
| 2234P  | NLS Merged Translations                        |
| 3234P  | NLS Pseudo Translation                         |
| 313P   | OpenSolaris                                    |
| 309P   | Oracle JRockit Virtual Edition x86 (32-bit)    |
| 311P   | Oracle JRockit Virtual Edition x86-64 (64-bit) |
| 506P   | Oracle Solaris Express                         |
| 453P   | Oracle Solaris on SPARC (32-bit)               |
| 23P    | Oracle Solaris on SPARC (64-bit)               |
| 173P   | Oracle Solaris on x86 (32-bit)                 |
| 267P   | Oracle Solaris on x86-64 (64-bit)              |
| 511P   | QNX UNIX                                       |
| 28P    | SCO UNIX                                       |
| 505P   | SPARC                                          |
| 550P   | StorageTek Hardware                            |
| 619P   | Stratus PA-RISC VOS                            |
| 26P    | Symbian EPOC                                   |
| 555P   | Talari                                         |
| 532P   | Tekelec                                        |
| 316P   | Unisys OS 2200                                 |
| 520P   | VxWorks                                        |
| 280P   | x86 32 bit                                     |
| 282P   | x86 64 bit                                     |

| Code   | Language                                       |
|--------|------------------------------------------------|
| 67L    | Albanian (SQ)                                  |
| 8L     | Arabic (AR)                                    |
| 26L    | Brazilian Portuguese (PTB)                     |
| 101L   | Bulgarian (BG)                                 |
| 3L     | Canadian French (FRC)                          |
| 102L   | Catalan (CA)                                   |
| 103L   | Croatian (HR)                                  |
| 66L    | Cyrillic Kazakh (CKK)                          |
| 62L    | Cyrillic Serbian (CSR)                         |
| 30L    | Czech (CS)                                     |
| 5L     | Danish (DK)                                    |
| 6L     | Dutch (NL)                                     |
| 118L   | ESTONIAN (ET)                                  |
| 7L     | Finnish (SF)                                   |
| 2L     | French (F)                                     |
| 4L     | German (D)                                     |
| 104L   | Greek (EL)                                     |
| 107L   | Hebrew (IW)                                    |
| 28L    | Hungarian (HU)                                 |
| 106L   | Icelandic (IS)                                 |
| 46L    | Indonesian (IN)                                |
| 108L   | Italian (I)                                    |
| 15L    | Japanese (JA)                                  |
| 16L    | Korean (KO)                                    |
| 29L    | Latin American Spanish (ESA)                   |
| 63L    | Latin Serbian (LSR)                            |
| 119L   | LATVIAN (LV)                                   |
| 109L   | Lithuanian (LT)                                |
| 10L    | Norwegian (N)                                  |
| 110L   | Polish (PL)                                    |
| 18L    | Portuguese (PT)                                |
| 111L   | Romanian (RO)                                  |
| 112L   | Russian (RU)                                   |
| 14L    | Simplified Chinese (ZHS)                       |
| 113L   | Slovak (SK)                                    |
| 114L   | Slovenian (SL)                                 |
| 11L    | Spanish (E)                                    |
| 13L    | Swedish (S)                                    |
| 115L   | Thai (TH)                                      |
| 117L   | Traditional Chinese (ZHT)                      |
| 116L   | Turkish (TR)                                   |
| 37L    | UK English (GB)                                |
| 39L    | Ukrainian (UK)                                 |
| 43L    | Vietnamese (VN)                                |
| 999L   | Worldwide Spanish (ESW)                        |
