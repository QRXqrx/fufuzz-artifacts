#  FunFuzz: Greybox Fuzzing with Function Significance.

Artifacts of Submission: _FunFuzz: Greybox Fuzzing with Function Significance_.

## Project structure

```text
AFLFun
---------------
.
├── README.md   # Project briefs
├── aflpp-fun   # Source code of FunFuzz prototype
└── data        # Experimental data

```

## Benchmark

Details of the real-world projects we select for evaluation. 
The targets and command arguments used for start fuzz campaigns can be found in our paper.

| Project       | Version / Tag | Included Targets              | Download Link                                                                                              |
|---------------|---------------|-------------------------------|------------------------------------------------------------------------------------------------------------|
| bintils       | 2.28          | cxxfilt, nm, objdump, readelf | https://ftp.gnu.org/gnu/binutils/binutils-2.28.tar.gz                                                      |
| libjpeg-turbo | 1.5.1         | djpeg                         | https://github.com/libjpeg-turbo/libjpeg-turbo/archive/refs/tags/1.5.1.tar.gz                              |
| libpng        | 1.6.29        | readpng                       | https://sourceforge.net/projects/libpng/files/libpng16/older-releases/1.6.29/libpng-1.6.29.tar.gz/download |
| mupdf         | 3.06          | mutool                        | https://mupdf.com/downloads/archive/mupdf-1.9-source.tar.gz                                                |
| tcpdump       | 4.9.0         | tcpdump                       | https://github.com/the-tcpdump-group/tcpdump/archive/refs/tags/tcpdump-4.9.0.tar.gz                        |
| libxml2       | 2.9.4         | xmllint                       | https://github.com/GNOME/libxml2/archive/refs/tags/v2.9.4.tar.gz                                           |
| mjs           | 2.20.0        | mjs                           | https://github.com/cesanta/mjs/archive/refs/tags/2.20.0.tar.gz                                             |

## Supported environments

| Env name            | Description                                                |
|---------------------|------------------------------------------------------------|
| AFL_FUN_TEMP        | path to funtemp                                            |
| AFL_LLVM_INSTRUMENT | fun, prefun                                                |
| FUN_DCC             | path to dcc process                                        |
| FUN_STATIC_FS       | whether using static fs values                             |
| FUN_UPDATE_PERIOD   | period of updating fs/awaking dcc process                  |
| FUN_SCHEDULE_OFF    | still computing sig_score, but does not use fun scheduling |
| FUN_LOG             | whether using fun logmode                                  |

