# Oracle Patch Downloader

The Oracle Patch Downloader can be used to download a list of patches from oracle.

## Precoditions

- java >= 11
- maven >= 3.9
- Oracle Support Account

## Installation

```sh
git clone git@github.com:ojehle/H35_OraclePatchDownloader.git
cd H35_OraclePatchDownloader
mvn install
cd target
## verfiy build, you can copy the file (its complete with all dependencies)
java -jar OraclePatchDownloader-1.0.1.jar 
```


## Usage

You can use the tool to download a list of patches, it accepts multiple -x or a list of patches delimited by comma.
the regex can be used to filter out the files
 
```sh
 -h : --help        help text

 -d : --directory   output folder, default user home

 -x : --patch       comma separated list of patches or multiple possible

 -f : --patchfile   patch list as file, one patch per line , line starting with # is ignored, format p12345678, 12345678

 -t : --plattform   Plattform Code 226P (Linux X86_64) 

 -r : --regex       regex for file filter, multiple possible

 -u : --user        email/userid

 -p : --password    password

 -c : --check       check downloaded files against patchlist (-x: --patch) 
```

```sh
java -jar OraclePatchDownloader-1.0.1.jar -u user@h35.li -p password -x 200000 -t 226P -r  ".*1900.*" -r  ".*19190.*" -d $HOME/Downloads
```



## Plattform Codes (-t)

| Code  | Plattform |
| ----- | -------------------------------------|
| 537P| Acme Packet 1100|  
| 529P| Acme Packet 3820|
| 540P| Acme Packet 3900|
| 561P| Acme Packet 3950|
| 530P| Acme Packet 4500|
| 538P| Acme Packet 4600|
| 560P| Acme Packet 4900|
| 534P| Acme Packet 6100|
| 531P| Acme Packet 6300|
| 551P| Acme Packet 6350|
| 527P| Acme Packet OS|
| 512P| Apple iOS|
| 293P| Apple Mac OS X (Intel) (32-bit)|
| 522P| Apple Mac OS X (Intel) (64-bit)|
| 421P| Apple Mac OS X (PowerPC)|
| 553P| Apple macOS|
| 559P| Apple macOS ARM (64-bit)|
| 516P| Embedded Linux ARM|
| 521P| Embedded Linux on cnMIPS|
| 519P| Embedded Linux on POWER e500v2|
| 517P| Embedded Linux on POWER Systems|
| 294P| Embedded Linux SH4|
| 515P| Embedded Linux x86|
| 228P| FreeBSD - x86|
| 361P| Fujitsu BS2000|
| 312P| Fujitsu BS2000/OSD (SQ series)|
| 285P| Fujitsu BS2000/OSD (SX series)|
| 504P| Fujitsu MSP-EX|
| 513P| Google Android|
| 554P| Google Android 9|
| 549P| HP NonStop (Guardian) on x86|
| 548P| HP NonStop (OSS) on x86|
| 304P| HP NonStop Itanium (Guardian)|
| 308P| HP NonStop Itanium (OSS)|
| 303P| HP NonStop S-series (Guardian)|
| 89P| HP OpenVMS Alpha|
| 243P| HP OpenVMS Itanium|
| 1P| HP OpenVMS VAX|
| 87P| HP Tru64 UNIX|
| 197P| HP-UX Itanium|
| 278P| HP-UX Itanium (32-bit)|
| 999P| HP-UX PA-RISC (32-bit)|
| 59P| HP-UX PA-RISC (64-bit)|
| 299P| ia64|
| 319P| IBM AIX on POWER Systems (32-bit)|
| 212P| IBM AIX on POWER Systems (64-bit)|
| 43P| IBM i on POWER Systems|
| 211P| IBM S/390 Based Linux (31-bit)|
| 30P| IBM z/OS on System z|
| 314P| IBM z/VM on System z|
| 227P| IBM: Linux on POWER Big Endian Systems|
| 542P| IBM: Linux on POWER Little Endian Systems|
| 209P| IBM: Linux on System z|
| 297P| iTron|
| 528P| Linux ARM 32-bit VFP HardFP ABI|
| 523P| Linux ARM 32-bit VFP SoftFP ABI|
| 564P| Linux ARM 64 bit (DB19 OL79)|
| 541P| Linux ARM 64-bit|
| 214P| Linux Itanium|
| 556P| Linux MIPS 64-bit|
| 525P| Linux SPARC|
| 46P| Linux x86|
| 226P| Linux x86-64|
| 99999P| Metadata-Only Patch|
| 912P| Microsoft Windows (32-bit)|
| 558P| Microsoft Windows AArch64|
| 208P| Microsoft Windows Itanium (64-bit)|
| 539P| Microsoft Windows Phone|
| 233P| Microsoft Windows x64 (64-bit)|
| 276P| Monta Vista x86|
| 277P| Monta Vista x86-64|
| 536P| Net-Net 4250|
| 533P| Net-Net 9200|
| 547P| Netra Server X5-2 for Communications|
| 535P| Netra X3-2 for Acme Packet|
| 1234P| NLS Generic Platform|
| 2234P| NLS Merged Translations|
| 3234P| NLS Pseudo Translation|
| 313P| OpenSolaris|
| 309P| Oracle JRockit Virtual Edition x86 (32-bit)|
| 311P| Oracle JRockit Virtual Edition x86-64 (64-bit)|
| 506P| Oracle Solaris Express|
| 453P| Oracle Solaris on SPARC (32-bit)|
| 23P| Oracle Solaris on SPARC (64-bit)|
| 173P| Oracle Solaris on x86 (32-bit)|
| 267P| Oracle Solaris on x86-64 (64-bit)|
| 511P| QNX UNIX|
| 28P| SCO UNIX|
| 505P| SPARC|
| 550P| StorageTek Hardware|
| 619P| Stratus PA-RISC VOS|
| 26P| Symbian EPOC|
| 555P| Talari|
| 532P| Tekelec|
| 316P| Unisys OS 2200|
| 520P| VxWorks|
| 280P| x86 32 bit|
| 282P| x86 64 bit|
