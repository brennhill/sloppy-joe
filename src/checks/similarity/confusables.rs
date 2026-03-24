//! Unicode confusables map for homoglyph detection.
//! Generated from https://www.unicode.org/Public/security/latest/confusables.txt
//! Filtered to BMP single-char -> ASCII a-z/0-9 mappings (excludes math alphanumerics).

use std::collections::HashMap;
use std::sync::LazyLock;

/// Lookup table: Unicode confusable character -> ASCII equivalent.
/// Used by HomoglyphGen to normalize lookalike characters in package names.
static CONFUSABLES: LazyLock<HashMap<char, char>> = LazyLock::new(|| {
    let entries: &[(char, char)] = &[
        ('\u{00D7}', 'x'), // MULTIPLICATION SIGN
        ('\u{00FE}', 'p'), // LATIN SMALL LETTER THORN
        ('\u{0131}', 'i'), // LATIN SMALL LETTER DOTLESS I
        ('\u{017F}', 'f'), // LATIN SMALL LETTER LONG S
        ('\u{0184}', 'b'), // LATIN CAPITAL LETTER TONE SIX
        ('\u{018D}', 'g'), // LATIN SMALL LETTER TURNED DELTA
        ('\u{0192}', 'f'), // LATIN SMALL LETTER F WITH HOOK
        ('\u{0196}', 'l'), // LATIN CAPITAL LETTER IOTA
        ('\u{01A6}', 'r'), // LATIN LETTER YR
        ('\u{01A7}', '2'), // LATIN CAPITAL LETTER TONE TWO
        ('\u{01B7}', '3'), // LATIN CAPITAL LETTER EZH
        ('\u{01BC}', '5'), // LATIN CAPITAL LETTER TONE FIVE
        ('\u{01BD}', 's'), // LATIN SMALL LETTER TONE FIVE
        ('\u{01BF}', 'p'), // LATIN LETTER WYNN
        ('\u{01C0}', 'l'), // LATIN LETTER DENTAL CLICK
        ('\u{021C}', '3'), // LATIN CAPITAL LETTER YOGH
        ('\u{0222}', '8'), // LATIN CAPITAL LETTER OU
        ('\u{0223}', '8'), // LATIN SMALL LETTER OU
        ('\u{0251}', 'a'), // LATIN SMALL LETTER ALPHA
        ('\u{0261}', 'g'), // LATIN SMALL LETTER SCRIPT G
        ('\u{0263}', 'y'), // LATIN SMALL LETTER GAMMA
        ('\u{0269}', 'i'), // LATIN SMALL LETTER IOTA
        ('\u{026A}', 'i'), // LATIN LETTER SMALL CAPITAL I
        ('\u{026F}', 'w'), // LATIN SMALL LETTER TURNED M
        ('\u{028B}', 'u'), // LATIN SMALL LETTER V WITH HOOK
        ('\u{028F}', 'y'), // LATIN LETTER SMALL CAPITAL Y
        ('\u{02DB}', 'i'), // OGONEK
        ('\u{037A}', 'i'), // GREEK YPOGEGRAMMENI
        ('\u{037F}', 'j'), // GREEK CAPITAL LETTER YOT
        ('\u{0391}', 'a'), // GREEK CAPITAL LETTER ALPHA
        ('\u{0392}', 'b'), // GREEK CAPITAL LETTER BETA
        ('\u{0395}', 'e'), // GREEK CAPITAL LETTER EPSILON
        ('\u{0396}', 'z'), // GREEK CAPITAL LETTER ZETA
        ('\u{0397}', 'h'), // GREEK CAPITAL LETTER ETA
        ('\u{0399}', 'l'), // GREEK CAPITAL LETTER IOTA
        ('\u{039A}', 'k'), // GREEK CAPITAL LETTER KAPPA
        ('\u{039C}', 'm'), // GREEK CAPITAL LETTER MU
        ('\u{039D}', 'n'), // GREEK CAPITAL LETTER NU
        ('\u{039F}', 'o'), // GREEK CAPITAL LETTER OMICRON
        ('\u{03A1}', 'p'), // GREEK CAPITAL LETTER RHO
        ('\u{03A4}', 't'), // GREEK CAPITAL LETTER TAU
        ('\u{03A5}', 'y'), // GREEK CAPITAL LETTER UPSILON
        ('\u{03A7}', 'x'), // GREEK CAPITAL LETTER CHI
        ('\u{03B1}', 'a'), // GREEK SMALL LETTER ALPHA
        ('\u{03B3}', 'y'), // GREEK SMALL LETTER GAMMA
        ('\u{03B9}', 'i'), // GREEK SMALL LETTER IOTA
        ('\u{03BD}', 'v'), // GREEK SMALL LETTER NU
        ('\u{03BF}', 'o'), // GREEK SMALL LETTER OMICRON
        ('\u{03C1}', 'p'), // GREEK SMALL LETTER RHO
        ('\u{03C3}', 'o'), // GREEK SMALL LETTER SIGMA
        ('\u{03C5}', 'u'), // GREEK SMALL LETTER UPSILON
        ('\u{03D2}', 'y'), // GREEK UPSILON WITH HOOK SYMBOL
        ('\u{03DC}', 'f'), // GREEK LETTER DIGAMMA
        ('\u{03E8}', '2'), // COPTIC CAPITAL LETTER HORI
        ('\u{03EC}', '6'), // COPTIC CAPITAL LETTER SHIMA
        ('\u{03ED}', 'o'), // COPTIC SMALL LETTER SHIMA
        ('\u{03F1}', 'p'), // GREEK RHO SYMBOL
        ('\u{03F2}', 'c'), // GREEK LUNATE SIGMA SYMBOL
        ('\u{03F3}', 'j'), // GREEK LETTER YOT
        ('\u{03F8}', 'p'), // GREEK SMALL LETTER SHO
        ('\u{03F9}', 'c'), // GREEK CAPITAL LUNATE SIGMA SYMBOL
        ('\u{03FA}', 'm'), // GREEK CAPITAL LETTER SAN
        ('\u{0405}', 's'), // CYRILLIC CAPITAL LETTER DZE
        ('\u{0406}', 'l'), // CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I
        ('\u{0408}', 'j'), // CYRILLIC CAPITAL LETTER JE
        ('\u{0410}', 'a'), // CYRILLIC CAPITAL LETTER A
        ('\u{0412}', 'b'), // CYRILLIC CAPITAL LETTER VE
        ('\u{0415}', 'e'), // CYRILLIC CAPITAL LETTER IE
        ('\u{0417}', '3'), // CYRILLIC CAPITAL LETTER ZE
        ('\u{041A}', 'k'), // CYRILLIC CAPITAL LETTER KA
        ('\u{041C}', 'm'), // CYRILLIC CAPITAL LETTER EM
        ('\u{041D}', 'h'), // CYRILLIC CAPITAL LETTER EN
        ('\u{041E}', 'o'), // CYRILLIC CAPITAL LETTER O
        ('\u{0420}', 'p'), // CYRILLIC CAPITAL LETTER ER
        ('\u{0421}', 'c'), // CYRILLIC CAPITAL LETTER ES
        ('\u{0422}', 't'), // CYRILLIC CAPITAL LETTER TE
        ('\u{0423}', 'y'), // CYRILLIC CAPITAL LETTER U
        ('\u{0425}', 'x'), // CYRILLIC CAPITAL LETTER HA
        ('\u{042C}', 'b'), // CYRILLIC CAPITAL LETTER SOFT SIGN
        ('\u{0430}', 'a'), // CYRILLIC SMALL LETTER A
        ('\u{0431}', '6'), // CYRILLIC SMALL LETTER BE
        ('\u{0433}', 'r'), // CYRILLIC SMALL LETTER GHE
        ('\u{0435}', 'e'), // CYRILLIC SMALL LETTER IE
        ('\u{043E}', 'o'), // CYRILLIC SMALL LETTER O
        ('\u{0440}', 'p'), // CYRILLIC SMALL LETTER ER
        ('\u{0441}', 'c'), // CYRILLIC SMALL LETTER ES
        ('\u{0443}', 'y'), // CYRILLIC SMALL LETTER U
        ('\u{0445}', 'x'), // CYRILLIC SMALL LETTER HA
        ('\u{0448}', 'w'), // CYRILLIC SMALL LETTER SHA
        ('\u{0455}', 's'), // CYRILLIC SMALL LETTER DZE
        ('\u{0456}', 'i'), // CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
        ('\u{0458}', 'j'), // CYRILLIC SMALL LETTER JE
        ('\u{0461}', 'w'), // CYRILLIC SMALL LETTER OMEGA
        ('\u{0474}', 'v'), // CYRILLIC CAPITAL LETTER IZHITSA
        ('\u{0475}', 'v'), // CYRILLIC SMALL LETTER IZHITSA
        ('\u{04AE}', 'y'), // CYRILLIC CAPITAL LETTER STRAIGHT U
        ('\u{04AF}', 'y'), // CYRILLIC SMALL LETTER STRAIGHT U
        ('\u{04BB}', 'h'), // CYRILLIC SMALL LETTER SHHA
        ('\u{04BD}', 'e'), // CYRILLIC SMALL LETTER ABKHASIAN CHE
        ('\u{04C0}', 'l'), // CYRILLIC LETTER PALOCHKA
        ('\u{04CF}', 'l'), // CYRILLIC SMALL LETTER PALOCHKA
        ('\u{04E0}', '3'), // CYRILLIC CAPITAL LETTER ABKHASIAN DZE
        ('\u{0501}', 'd'), // CYRILLIC SMALL LETTER KOMI DE
        ('\u{050C}', 'g'), // CYRILLIC CAPITAL LETTER KOMI SJE
        ('\u{051B}', 'q'), // CYRILLIC SMALL LETTER QA
        ('\u{051C}', 'w'), // CYRILLIC CAPITAL LETTER WE
        ('\u{051D}', 'w'), // CYRILLIC SMALL LETTER WE
        ('\u{054D}', 'u'), // ARMENIAN CAPITAL LETTER SEH
        ('\u{054F}', 's'), // ARMENIAN CAPITAL LETTER TIWN
        ('\u{0555}', 'o'), // ARMENIAN CAPITAL LETTER OH
        ('\u{0561}', 'w'), // ARMENIAN SMALL LETTER AYB
        ('\u{0563}', 'q'), // ARMENIAN SMALL LETTER GIM
        ('\u{0566}', 'q'), // ARMENIAN SMALL LETTER ZA
        ('\u{0570}', 'h'), // ARMENIAN SMALL LETTER HO
        ('\u{0578}', 'n'), // ARMENIAN SMALL LETTER VO
        ('\u{057C}', 'n'), // ARMENIAN SMALL LETTER RA
        ('\u{057D}', 'u'), // ARMENIAN SMALL LETTER SEH
        ('\u{0581}', 'g'), // ARMENIAN SMALL LETTER CO
        ('\u{0582}', 'i'), // ARMENIAN SMALL LETTER YIWN
        ('\u{0584}', 'f'), // ARMENIAN SMALL LETTER KEH
        ('\u{0585}', 'o'), // ARMENIAN SMALL LETTER OH
        ('\u{05C0}', 'l'), // HEBREW PUNCTUATION PASEQ
        ('\u{05D5}', 'l'), // HEBREW LETTER VAV
        ('\u{05D8}', 'v'), // HEBREW LETTER TET
        ('\u{05DF}', 'l'), // HEBREW LETTER FINAL NUN
        ('\u{05E1}', 'o'), // HEBREW LETTER SAMEKH
        ('\u{0627}', 'l'), // ARABIC LETTER ALEF
        ('\u{0647}', 'o'), // ARABIC LETTER HEH
        ('\u{0661}', 'l'), // ARABIC-INDIC DIGIT ONE
        ('\u{0665}', 'o'), // ARABIC-INDIC DIGIT FIVE
        ('\u{0667}', 'v'), // ARABIC-INDIC DIGIT SEVEN
        ('\u{06BE}', 'o'), // ARABIC LETTER HEH DOACHASHMEE
        ('\u{06C1}', 'o'), // ARABIC LETTER HEH GOAL
        ('\u{06D5}', 'o'), // ARABIC LETTER AE
        ('\u{06F1}', 'l'), // EXTENDED ARABIC-INDIC DIGIT ONE
        ('\u{06F5}', 'o'), // EXTENDED ARABIC-INDIC DIGIT FIVE
        ('\u{06F7}', 'v'), // EXTENDED ARABIC-INDIC DIGIT SEVEN
        ('\u{07C0}', 'o'), // NKO DIGIT ZERO
        ('\u{07CA}', 'l'), // NKO LETTER A
        ('\u{0966}', 'o'), // DEVANAGARI DIGIT ZERO
        ('\u{0969}', '3'), // DEVANAGARI DIGIT THREE
        ('\u{09E6}', 'o'), // BENGALI DIGIT ZERO
        ('\u{09EA}', '8'), // BENGALI DIGIT FOUR
        ('\u{09ED}', '9'), // BENGALI DIGIT SEVEN
        ('\u{0A66}', 'o'), // GURMUKHI DIGIT ZERO
        ('\u{0A67}', '9'), // GURMUKHI DIGIT ONE
        ('\u{0A6A}', '8'), // GURMUKHI DIGIT FOUR
        ('\u{0AE6}', 'o'), // GUJARATI DIGIT ZERO
        ('\u{0AE9}', '3'), // GUJARATI DIGIT THREE
        ('\u{0B03}', '8'), // ORIYA SIGN VISARGA
        ('\u{0B20}', 'o'), // ORIYA LETTER TTHA
        ('\u{0B66}', 'o'), // ORIYA DIGIT ZERO
        ('\u{0B68}', '9'), // ORIYA DIGIT TWO
        ('\u{0BE6}', 'o'), // TAMIL DIGIT ZERO
        ('\u{0C02}', 'o'), // TELUGU SIGN ANUSVARA
        ('\u{0C66}', 'o'), // TELUGU DIGIT ZERO
        ('\u{0C82}', 'o'), // KANNADA SIGN ANUSVARA
        ('\u{0CE6}', 'o'), // KANNADA DIGIT ZERO
        ('\u{0D02}', 'o'), // MALAYALAM SIGN ANUSVARA
        ('\u{0D1F}', 's'), // MALAYALAM LETTER TTA
        ('\u{0D20}', 'o'), // MALAYALAM LETTER TTHA
        ('\u{0D66}', 'o'), // MALAYALAM DIGIT ZERO
        ('\u{0D6D}', '9'), // MALAYALAM DIGIT SEVEN
        ('\u{0D82}', 'o'), // SINHALA SIGN ANUSVARAYA
        ('\u{0E50}', 'o'), // THAI DIGIT ZERO
        ('\u{0ED0}', 'o'), // LAO DIGIT ZERO
        ('\u{1004}', 'c'), // MYANMAR LETTER NGA
        ('\u{101D}', 'o'), // MYANMAR LETTER WA
        ('\u{1040}', 'o'), // MYANMAR DIGIT ZERO
        ('\u{105A}', 'c'), // MYANMAR LETTER MON NGA
        ('\u{10E7}', 'y'), // GEORGIAN LETTER QAR
        ('\u{10FF}', 'o'), // GEORGIAN LETTER LABIAL SIGN
        ('\u{1200}', 'u'), // ETHIOPIC SYLLABLE HA
        ('\u{12D0}', 'o'), // ETHIOPIC SYLLABLE PHARYNGEAL A
        ('\u{13A0}', 'd'), // CHEROKEE LETTER A
        ('\u{13A1}', 'r'), // CHEROKEE LETTER E
        ('\u{13A2}', 't'), // CHEROKEE LETTER I
        ('\u{13A5}', 'i'), // CHEROKEE LETTER V
        ('\u{13A9}', 'y'), // CHEROKEE LETTER GI
        ('\u{13AA}', 'a'), // CHEROKEE LETTER GO
        ('\u{13AB}', 'j'), // CHEROKEE LETTER GU
        ('\u{13AC}', 'e'), // CHEROKEE LETTER GV
        ('\u{13B3}', 'w'), // CHEROKEE LETTER LA
        ('\u{13B7}', 'm'), // CHEROKEE LETTER LU
        ('\u{13BB}', 'h'), // CHEROKEE LETTER MI
        ('\u{13BD}', 'y'), // CHEROKEE LETTER MU
        ('\u{13C0}', 'g'), // CHEROKEE LETTER NAH
        ('\u{13C2}', 'h'), // CHEROKEE LETTER NI
        ('\u{13C3}', 'z'), // CHEROKEE LETTER NO
        ('\u{13CE}', '4'), // CHEROKEE LETTER SE
        ('\u{13CF}', 'b'), // CHEROKEE LETTER SI
        ('\u{13D2}', 'r'), // CHEROKEE LETTER SV
        ('\u{13D4}', 'w'), // CHEROKEE LETTER TA
        ('\u{13D5}', 's'), // CHEROKEE LETTER DE
        ('\u{13D9}', 'v'), // CHEROKEE LETTER DO
        ('\u{13DA}', 's'), // CHEROKEE LETTER DU
        ('\u{13DE}', 'l'), // CHEROKEE LETTER TLE
        ('\u{13DF}', 'c'), // CHEROKEE LETTER TLI
        ('\u{13E2}', 'p'), // CHEROKEE LETTER TLV
        ('\u{13E6}', 'k'), // CHEROKEE LETTER TSO
        ('\u{13E7}', 'd'), // CHEROKEE LETTER TSU
        ('\u{13EE}', '6'), // CHEROKEE LETTER WV
        ('\u{13F3}', 'g'), // CHEROKEE LETTER YU
        ('\u{13F4}', 'b'), // CHEROKEE LETTER YV
        ('\u{142F}', 'v'), // CANADIAN SYLLABICS PE
        ('\u{144C}', 'u'), // CANADIAN SYLLABICS TE
        ('\u{146D}', 'p'), // CANADIAN SYLLABICS KI
        ('\u{146F}', 'd'), // CANADIAN SYLLABICS KO
        ('\u{1472}', 'b'), // CANADIAN SYLLABICS KA
        ('\u{148D}', 'j'), // CANADIAN SYLLABICS CO
        ('\u{14AA}', 'l'), // CANADIAN SYLLABICS MA
        ('\u{14BF}', '2'), // CANADIAN SYLLABICS SAYISI M
        ('\u{1541}', 'x'), // CANADIAN SYLLABICS SAYISI YI
        ('\u{157C}', 'h'), // CANADIAN SYLLABICS NUNAVUT H
        ('\u{157D}', 'x'), // CANADIAN SYLLABICS HK
        ('\u{1587}', 'r'), // CANADIAN SYLLABICS TLHI
        ('\u{15AF}', 'b'), // CANADIAN SYLLABICS AIVILIK B
        ('\u{15B4}', 'f'), // CANADIAN SYLLABICS BLACKFOOT WE
        ('\u{15C5}', 'a'), // CANADIAN SYLLABICS CARRIER GHO
        ('\u{15DE}', 'd'), // CANADIAN SYLLABICS CARRIER THE
        ('\u{15EA}', 'd'), // CANADIAN SYLLABICS CARRIER PE
        ('\u{15F0}', 'm'), // CANADIAN SYLLABICS CARRIER GO
        ('\u{15F7}', 'b'), // CANADIAN SYLLABICS CARRIER KHE
        ('\u{166D}', 'x'), // CANADIAN SYLLABICS CHI SIGN
        ('\u{166E}', 'x'), // CANADIAN SYLLABICS FULL STOP
        ('\u{16B7}', 'x'), // RUNIC LETTER GEBO GYFU G
        ('\u{16C1}', 'l'), // RUNIC LETTER ISAZ IS ISS I
        ('\u{16D5}', 'k'), // RUNIC LETTER OPEN-P
        ('\u{16D6}', 'm'), // RUNIC LETTER EHWAZ EH E
        ('\u{17E0}', 'o'), // KHMER DIGIT ZERO
        ('\u{1D04}', 'c'), // LATIN LETTER SMALL CAPITAL C
        ('\u{1D0F}', 'o'), // LATIN LETTER SMALL CAPITAL O
        ('\u{1D11}', 'o'), // LATIN SMALL LETTER SIDEWAYS O
        ('\u{1D1C}', 'u'), // LATIN LETTER SMALL CAPITAL U
        ('\u{1D20}', 'v'), // LATIN LETTER SMALL CAPITAL V
        ('\u{1D21}', 'w'), // LATIN LETTER SMALL CAPITAL W
        ('\u{1D22}', 'z'), // LATIN LETTER SMALL CAPITAL Z
        ('\u{1D26}', 'r'), // GREEK LETTER SMALL CAPITAL GAMMA
        ('\u{1D83}', 'g'), // LATIN SMALL LETTER G WITH PALATAL HOOK
        ('\u{1D8C}', 'y'), // LATIN SMALL LETTER V WITH PALATAL HOOK
        ('\u{1E9D}', 'f'), // LATIN SMALL LETTER LONG S WITH HIGH STROKE
        ('\u{1EFF}', 'y'), // LATIN SMALL LETTER Y WITH LOOP
        ('\u{1FBE}', 'i'), // GREEK PROSGEGRAMMENI
        ('\u{2102}', 'c'), // DOUBLE-STRUCK CAPITAL C
        ('\u{210A}', 'g'), // SCRIPT SMALL G
        ('\u{210B}', 'h'), // SCRIPT CAPITAL H
        ('\u{210C}', 'h'), // BLACK-LETTER CAPITAL H
        ('\u{210D}', 'h'), // DOUBLE-STRUCK CAPITAL H
        ('\u{210E}', 'h'), // PLANCK CONSTANT
        ('\u{2110}', 'l'), // SCRIPT CAPITAL I
        ('\u{2111}', 'l'), // BLACK-LETTER CAPITAL I
        ('\u{2112}', 'l'), // SCRIPT CAPITAL L
        ('\u{2113}', 'l'), // SCRIPT SMALL L
        ('\u{2115}', 'n'), // DOUBLE-STRUCK CAPITAL N
        ('\u{2119}', 'p'), // DOUBLE-STRUCK CAPITAL P
        ('\u{211A}', 'q'), // DOUBLE-STRUCK CAPITAL Q
        ('\u{211B}', 'r'), // SCRIPT CAPITAL R
        ('\u{211C}', 'r'), // BLACK-LETTER CAPITAL R
        ('\u{211D}', 'r'), // DOUBLE-STRUCK CAPITAL R
        ('\u{2124}', 'z'), // DOUBLE-STRUCK CAPITAL Z
        ('\u{2128}', 'z'), // BLACK-LETTER CAPITAL Z
        ('\u{212A}', 'k'), // KELVIN SIGN
        ('\u{212C}', 'b'), // SCRIPT CAPITAL B
        ('\u{212D}', 'c'), // BLACK-LETTER CAPITAL C
        ('\u{212E}', 'e'), // ESTIMATED SYMBOL
        ('\u{212F}', 'e'), // SCRIPT SMALL E
        ('\u{2130}', 'e'), // SCRIPT CAPITAL E
        ('\u{2131}', 'f'), // SCRIPT CAPITAL F
        ('\u{2133}', 'm'), // SCRIPT CAPITAL M
        ('\u{2134}', 'o'), // SCRIPT SMALL O
        ('\u{2139}', 'i'), // INFORMATION SOURCE
        ('\u{213D}', 'y'), // DOUBLE-STRUCK SMALL GAMMA
        ('\u{2145}', 'd'), // DOUBLE-STRUCK ITALIC CAPITAL D
        ('\u{2146}', 'd'), // DOUBLE-STRUCK ITALIC SMALL D
        ('\u{2147}', 'e'), // DOUBLE-STRUCK ITALIC SMALL E
        ('\u{2148}', 'i'), // DOUBLE-STRUCK ITALIC SMALL I
        ('\u{2149}', 'j'), // DOUBLE-STRUCK ITALIC SMALL J
        ('\u{2160}', 'l'), // ROMAN NUMERAL ONE
        ('\u{2164}', 'v'), // ROMAN NUMERAL FIVE
        ('\u{2169}', 'x'), // ROMAN NUMERAL TEN
        ('\u{216C}', 'l'), // ROMAN NUMERAL FIFTY
        ('\u{216D}', 'c'), // ROMAN NUMERAL ONE HUNDRED
        ('\u{216E}', 'd'), // ROMAN NUMERAL FIVE HUNDRED
        ('\u{216F}', 'm'), // ROMAN NUMERAL ONE THOUSAND
        ('\u{2170}', 'i'), // SMALL ROMAN NUMERAL ONE
        ('\u{2174}', 'v'), // SMALL ROMAN NUMERAL FIVE
        ('\u{2179}', 'x'), // SMALL ROMAN NUMERAL TEN
        ('\u{217C}', 'l'), // SMALL ROMAN NUMERAL FIFTY
        ('\u{217D}', 'c'), // SMALL ROMAN NUMERAL ONE HUNDRED
        ('\u{217E}', 'd'), // SMALL ROMAN NUMERAL FIVE HUNDRED
        ('\u{2223}', 'l'), // DIVIDES
        ('\u{2228}', 'v'), // LOGICAL OR
        ('\u{222A}', 'u'), // UNION
        ('\u{22A4}', 't'), // DOWN TACK
        ('\u{22C1}', 'v'), // N-ARY LOGICAL OR
        ('\u{22C3}', 'u'), // N-ARY UNION
        ('\u{22FF}', 'e'), // Z NOTATION BAG MEMBERSHIP
        ('\u{2373}', 'i'), // APL FUNCTIONAL SYMBOL IOTA
        ('\u{2374}', 'p'), // APL FUNCTIONAL SYMBOL RHO
        ('\u{237A}', 'a'), // APL FUNCTIONAL SYMBOL ALPHA
        ('\u{23FD}', 'l'), // POWER ON SYMBOL
        ('\u{2573}', 'x'), // BOX DRAWINGS LIGHT DIAGONAL CROSS
        ('\u{27D9}', 't'), // LARGE DOWN TACK
        ('\u{292B}', 'x'), // RISING DIAGONAL CROSSING FALLING DIAGONAL
        ('\u{292C}', 'x'), // FALLING DIAGONAL CROSSING RISING DIAGONAL
        ('\u{2A2F}', 'x'), // VECTOR OR CROSS PRODUCT
        ('\u{2C82}', 'b'), // COPTIC CAPITAL LETTER VIDA
        ('\u{2C85}', 'r'), // COPTIC SMALL LETTER GAMMA
        ('\u{2C8E}', 'h'), // COPTIC CAPITAL LETTER HATE
        ('\u{2C92}', 'l'), // COPTIC CAPITAL LETTER IAUDA
        ('\u{2C93}', 'i'), // COPTIC SMALL LETTER IAUDA
        ('\u{2C94}', 'k'), // COPTIC CAPITAL LETTER KAPA
        ('\u{2C98}', 'm'), // COPTIC CAPITAL LETTER MI
        ('\u{2C9A}', 'n'), // COPTIC CAPITAL LETTER NI
        ('\u{2C9C}', '3'), // COPTIC CAPITAL LETTER KSI
        ('\u{2C9E}', 'o'), // COPTIC CAPITAL LETTER O
        ('\u{2C9F}', 'o'), // COPTIC SMALL LETTER O
        ('\u{2CA2}', 'p'), // COPTIC CAPITAL LETTER RO
        ('\u{2CA3}', 'p'), // COPTIC SMALL LETTER RO
        ('\u{2CA4}', 'c'), // COPTIC CAPITAL LETTER SIMA
        ('\u{2CA5}', 'c'), // COPTIC SMALL LETTER SIMA
        ('\u{2CA6}', 't'), // COPTIC CAPITAL LETTER TAU
        ('\u{2CA8}', 'y'), // COPTIC CAPITAL LETTER UA
        ('\u{2CA9}', 'y'), // COPTIC SMALL LETTER UA
        ('\u{2CAC}', 'x'), // COPTIC CAPITAL LETTER KHI
        ('\u{2CBD}', 'w'), // COPTIC SMALL LETTER CRYPTOGRAMMIC NI
        ('\u{2CC4}', '3'), // COPTIC CAPITAL LETTER OLD COPTIC SHEI
        ('\u{2CCA}', '9'), // COPTIC CAPITAL LETTER DIALECT-P HORI
        ('\u{2CCB}', '9'), // COPTIC SMALL LETTER DIALECT-P HORI
        ('\u{2CCC}', '3'), // COPTIC CAPITAL LETTER OLD COPTIC HORI
        ('\u{2CCE}', 'p'), // COPTIC CAPITAL LETTER OLD COPTIC HA
        ('\u{2CCF}', 'p'), // COPTIC SMALL LETTER OLD COPTIC HA
        ('\u{2CD0}', 'l'), // COPTIC CAPITAL LETTER L-SHAPED HA
        ('\u{2CD2}', '6'), // COPTIC CAPITAL LETTER OLD COPTIC HEI
        ('\u{2CD3}', '6'), // COPTIC SMALL LETTER OLD COPTIC HEI
        ('\u{2CDC}', '6'), // COPTIC CAPITAL LETTER OLD NUBIAN SHIMA
        ('\u{2D38}', 'v'), // TIFINAGH LETTER YADH
        ('\u{2D39}', 'e'), // TIFINAGH LETTER YADD
        ('\u{2D4F}', 'l'), // TIFINAGH LETTER YAN
        ('\u{2D54}', 'o'), // TIFINAGH LETTER YAR
        ('\u{2D55}', 'q'), // TIFINAGH LETTER YARR
        ('\u{2D5D}', 'x'), // TIFINAGH LETTER YATH
        ('\u{3007}', 'o'), // IDEOGRAPHIC NUMBER ZERO
        ('\u{A4D0}', 'b'), // LISU LETTER BA
        ('\u{A4D1}', 'p'), // LISU LETTER PA
        ('\u{A4D2}', 'd'), // LISU LETTER PHA
        ('\u{A4D3}', 'd'), // LISU LETTER DA
        ('\u{A4D4}', 't'), // LISU LETTER TA
        ('\u{A4D6}', 'g'), // LISU LETTER GA
        ('\u{A4D7}', 'k'), // LISU LETTER KA
        ('\u{A4D9}', 'j'), // LISU LETTER JA
        ('\u{A4DA}', 'c'), // LISU LETTER CA
        ('\u{A4DC}', 'z'), // LISU LETTER DZA
        ('\u{A4DD}', 'f'), // LISU LETTER TSA
        ('\u{A4DF}', 'm'), // LISU LETTER MA
        ('\u{A4E0}', 'n'), // LISU LETTER NA
        ('\u{A4E1}', 'l'), // LISU LETTER LA
        ('\u{A4E2}', 's'), // LISU LETTER SA
        ('\u{A4E3}', 'r'), // LISU LETTER ZHA
        ('\u{A4E6}', 'v'), // LISU LETTER HA
        ('\u{A4E7}', 'h'), // LISU LETTER XA
        ('\u{A4EA}', 'w'), // LISU LETTER WA
        ('\u{A4EB}', 'x'), // LISU LETTER SHA
        ('\u{A4EC}', 'y'), // LISU LETTER YA
        ('\u{A4EE}', 'a'), // LISU LETTER A
        ('\u{A4F0}', 'e'), // LISU LETTER E
        ('\u{A4F2}', 'l'), // LISU LETTER I
        ('\u{A4F3}', 'o'), // LISU LETTER O
        ('\u{A4F4}', 'u'), // LISU LETTER U
        ('\u{A644}', '2'), // CYRILLIC CAPITAL LETTER REVERSED DZE
        ('\u{A647}', 'i'), // CYRILLIC SMALL LETTER IOTA
        ('\u{A6DF}', 'v'), // BAMUM LETTER KO
        ('\u{A6EF}', '2'), // BAMUM LETTER KOGHOM
        ('\u{A731}', 's'), // LATIN LETTER SMALL CAPITAL S
        ('\u{A75A}', '2'), // LATIN CAPITAL LETTER R ROTUNDA
        ('\u{A76A}', '3'), // LATIN CAPITAL LETTER ET
        ('\u{A76E}', '9'), // LATIN CAPITAL LETTER CON
        ('\u{A798}', 'f'), // LATIN CAPITAL LETTER F WITH STROKE
        ('\u{A799}', 'f'), // LATIN SMALL LETTER F WITH STROKE
        ('\u{A79F}', 'u'), // LATIN SMALL LETTER VOLAPUK UE
        ('\u{A7AB}', '3'), // LATIN CAPITAL LETTER REVERSED OPEN E
        ('\u{A7B2}', 'j'), // LATIN CAPITAL LETTER J WITH CROSSED-TAIL
        ('\u{A7B3}', 'x'), // LATIN CAPITAL LETTER CHI
        ('\u{A7B4}', 'b'), // LATIN CAPITAL LETTER BETA
        ('\u{AB32}', 'e'), // LATIN SMALL LETTER BLACKLETTER E
        ('\u{AB35}', 'f'), // LATIN SMALL LETTER LENIS F
        ('\u{AB3D}', 'o'), // LATIN SMALL LETTER BLACKLETTER O
        ('\u{AB47}', 'r'), // LATIN SMALL LETTER R WITHOUT HANDLE
        ('\u{AB48}', 'r'), // LATIN SMALL LETTER DOUBLE R
        ('\u{AB4E}', 'u'), // LATIN SMALL LETTER U WITH SHORT RIGHT LEG
        ('\u{AB52}', 'u'), // LATIN SMALL LETTER U WITH LEFT HOOK
        ('\u{AB5A}', 'y'), // LATIN SMALL LETTER Y WITH SHORT RIGHT LEG
        ('\u{AB75}', 'i'), // CHEROKEE SMALL LETTER V
        ('\u{AB81}', 'r'), // CHEROKEE SMALL LETTER HU
        ('\u{AB83}', 'w'), // CHEROKEE SMALL LETTER LA
        ('\u{AB93}', 'z'), // CHEROKEE SMALL LETTER NO
        ('\u{ABA9}', 'v'), // CHEROKEE SMALL LETTER DO
        ('\u{ABAA}', 's'), // CHEROKEE SMALL LETTER DU
        ('\u{ABAF}', 'c'), // CHEROKEE SMALL LETTER TLI
        ('\u{FBA6}', 'o'), // ARABIC LETTER HEH GOAL ISOLATED FORM
        ('\u{FBA7}', 'o'), // ARABIC LETTER HEH GOAL FINAL FORM
        ('\u{FBA8}', 'o'), // ARABIC LETTER HEH GOAL INITIAL FORM
        ('\u{FBA9}', 'o'), // ARABIC LETTER HEH GOAL MEDIAL FORM
        ('\u{FBAA}', 'o'), // ARABIC LETTER HEH DOACHASHMEE ISOLATED FORM
        ('\u{FBAB}', 'o'), // ARABIC LETTER HEH DOACHASHMEE FINAL FORM
        ('\u{FBAC}', 'o'), // ARABIC LETTER HEH DOACHASHMEE INITIAL FORM
        ('\u{FBAD}', 'o'), // ARABIC LETTER HEH DOACHASHMEE MEDIAL FORM
        ('\u{FE8D}', 'l'), // ARABIC LETTER ALEF ISOLATED FORM
        ('\u{FE8E}', 'l'), // ARABIC LETTER ALEF FINAL FORM
        ('\u{FEE9}', 'o'), // ARABIC LETTER HEH ISOLATED FORM
        ('\u{FEEA}', 'o'), // ARABIC LETTER HEH FINAL FORM
        ('\u{FEEB}', 'o'), // ARABIC LETTER HEH INITIAL FORM
        ('\u{FEEC}', 'o'), // ARABIC LETTER HEH MEDIAL FORM
        ('\u{FF21}', 'a'), // FULLWIDTH LATIN CAPITAL LETTER A
        ('\u{FF22}', 'b'), // FULLWIDTH LATIN CAPITAL LETTER B
        ('\u{FF23}', 'c'), // FULLWIDTH LATIN CAPITAL LETTER C
        ('\u{FF25}', 'e'), // FULLWIDTH LATIN CAPITAL LETTER E
        ('\u{FF28}', 'h'), // FULLWIDTH LATIN CAPITAL LETTER H
        ('\u{FF29}', 'l'), // FULLWIDTH LATIN CAPITAL LETTER I
        ('\u{FF2A}', 'j'), // FULLWIDTH LATIN CAPITAL LETTER J
        ('\u{FF2B}', 'k'), // FULLWIDTH LATIN CAPITAL LETTER K
        ('\u{FF2D}', 'm'), // FULLWIDTH LATIN CAPITAL LETTER M
        ('\u{FF2E}', 'n'), // FULLWIDTH LATIN CAPITAL LETTER N
        ('\u{FF2F}', 'o'), // FULLWIDTH LATIN CAPITAL LETTER O
        ('\u{FF30}', 'p'), // FULLWIDTH LATIN CAPITAL LETTER P
        ('\u{FF33}', 's'), // FULLWIDTH LATIN CAPITAL LETTER S
        ('\u{FF34}', 't'), // FULLWIDTH LATIN CAPITAL LETTER T
        ('\u{FF38}', 'x'), // FULLWIDTH LATIN CAPITAL LETTER X
        ('\u{FF39}', 'y'), // FULLWIDTH LATIN CAPITAL LETTER Y
        ('\u{FF3A}', 'z'), // FULLWIDTH LATIN CAPITAL LETTER Z
        ('\u{FF41}', 'a'), // FULLWIDTH LATIN SMALL LETTER A
        ('\u{FF43}', 'c'), // FULLWIDTH LATIN SMALL LETTER C
        ('\u{FF45}', 'e'), // FULLWIDTH LATIN SMALL LETTER E
        ('\u{FF47}', 'g'), // FULLWIDTH LATIN SMALL LETTER G
        ('\u{FF48}', 'h'), // FULLWIDTH LATIN SMALL LETTER H
        ('\u{FF49}', 'i'), // FULLWIDTH LATIN SMALL LETTER I
        ('\u{FF4A}', 'j'), // FULLWIDTH LATIN SMALL LETTER J
        ('\u{FF4C}', 'l'), // FULLWIDTH LATIN SMALL LETTER L
        ('\u{FF4F}', 'o'), // FULLWIDTH LATIN SMALL LETTER O
        ('\u{FF50}', 'p'), // FULLWIDTH LATIN SMALL LETTER P
        ('\u{FF53}', 's'), // FULLWIDTH LATIN SMALL LETTER S
        ('\u{FF56}', 'v'), // FULLWIDTH LATIN SMALL LETTER V
        ('\u{FF58}', 'x'), // FULLWIDTH LATIN SMALL LETTER X
        ('\u{FF59}', 'y'), // FULLWIDTH LATIN SMALL LETTER Y
        ('\u{FFE8}', 'l'), // HALFWIDTH FORMS LIGHT VERTICAL
    ];
    entries.iter().copied().collect()
});

/// Normalize a name by replacing Unicode confusables with ASCII equivalents.
/// Returns the normalized string and whether any replacements were made.
pub fn normalize(name: &str) -> (String, bool) {
    let mut result = String::with_capacity(name.len());
    let mut replaced = false;
    for ch in name.chars() {
        if let Some(&ascii) = CONFUSABLES.get(&ch) {
            result.push(ascii);
            replaced = true;
        } else {
            result.push(ch);
        }
    }
    (result, replaced)
}

/// Number of confusable mappings in the table.
#[cfg(test)]
const MAP_SIZE: usize = 445;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_loads_correctly() {
        assert_eq!(CONFUSABLES.len(), MAP_SIZE);
    }

    #[test]
    fn cyrillic_a_maps_to_latin_a() {
        assert_eq!(CONFUSABLES.get(&'\u{0430}'), Some(&'a'));
    }

    #[test]
    fn greek_omicron_maps_to_latin_o() {
        assert_eq!(CONFUSABLES.get(&'\u{03BF}'), Some(&'o'));
    }

    #[test]
    fn normalize_replaces_confusables() {
        // Cyrillic 'е' (U+0435) -> Latin 'e'
        let (normalized, replaced) = normalize("r\u{0435}quests");
        assert_eq!(normalized, "requests");
        assert!(replaced);
    }

    #[test]
    fn normalize_preserves_ascii() {
        let (normalized, replaced) = normalize("requests");
        assert_eq!(normalized, "requests");
        assert!(!replaced);
    }

    #[test]
    fn greek_omicron_attack_detected() {
        // Greek omicron in 'react' -> should normalize to ASCII
        let (normalized, replaced) = normalize("re\u{03B1}ct");
        assert_eq!(normalized, "react");
        assert!(replaced);
    }
}
