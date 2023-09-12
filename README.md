#  FunFuzz: Greybox Fuzzing with Function Significance.

Artifacts of TOSEM Submission: _FunFuzz: Greybox Fuzzing with Function Significance_.

## Project structure

```text
AFLFun
---------------
.
├── README.md   # Project briefs
├── aflppfun    # Source code of our prototype
└── data        # Experimental data

```

## Benchmark

Details of the real-world projects we select for evaluation. 
The targets and command arguments used for start fuzz campaigns can be found in our paper.

| Project       | Version / Tag | Included Targets              | Download Link                                                                                              |
|---------------|---------------|-------------------------------|------------------------------------------------------------------------------------------------------------|
| bintils       | 2.28          | cxxfilt, nm, objdump, readelf | https://ftp.gnu.org/gnu/binutils/binutils-2.28.tar.gz                                                      |
| libjpeg-turbo | 1.5.1         | djpeg                         | https://github.com/libjpeg-turbo/libjpeg-turbo/archive/refs/tags/1.5.1.tar.gz                              |
| libpng        | 1.6.29        | pngtest                       | https://sourceforge.net/projects/libpng/files/libpng16/older-releases/1.6.29/libpng-1.6.29.tar.gz/download |
| mupdf         | 3.06          | mutool                        | https://mupdf.com/downloads/archive/mupdf-1.9-source.tar.gz                                                |
| tcpdump       | 4.9.0         | tcpdump                       | https://github.com/the-tcpdump-group/tcpdump/archive/refs/tags/tcpdump-4.9.0.tar.gz                        |
| libxml2       | 2.9.4         | xmllint                       | https://github.com/GNOME/libxml2/archive/refs/tags/v2.9.4.tar.gz                                           |

